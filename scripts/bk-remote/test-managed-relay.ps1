[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BinRoot,
    [Parameter(Mandatory=$true)][string]$EvidenceRoot,
    [Parameter(Mandatory=$true)][string]$RelayBindAddress,
    [Parameter(Mandatory=$true)][string]$RepoRoot
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$bin=(Resolve-Path -LiteralPath $BinRoot).Path
$root=[IO.Path]::GetFullPath($EvidenceRoot)
if(Test-Path $root){throw 'Existing E2E directory'}
foreach($exe in @('hbbs.exe','hbbr.exe','bk-remote-relayctl.exe')){
    if(!(Test-Path (Join-Path $bin $exe) -PathType Leaf)){throw "Missing test binary: $exe"}
}
$ipObj=Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -eq $RelayBindAddress -and $_.AddressState -eq 'Preferred' -and
    $_.InterfaceAlias -match '^vEthernet'
} | Select-Object -First 1
if(!$ipObj -or $RelayBindAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'){
    throw 'Test requires a local private virtual-switch IPv4 address'
}
$ip=$ipObj.IPAddress
$null=New-Item -ItemType Directory -Path $root
$loop='127.0.0.1'
$procs=[System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$repoDb=Join-Path (Resolve-Path -LiteralPath $RepoRoot).Path 'db_v2.sqlite3'
$oldDb=if(Test-Path $repoDb){(Get-FileHash $repoDb).Hash}else{''}
function Free-Group([string]$addr,[int[]]$offsets){
    foreach($i in 1..100){
        $port=Get-Random -Minimum 32000 -Maximum 57000
        $listeners=@()
        try{
            foreach($o in $offsets){
                $l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($addr),$port+$o)
                $l.Start()
                $listeners+= $l
            }
            return $port
        }catch{}finally{foreach($l in $listeners){$l.Stop()}}
    }
    throw 'No available test ports'
}
function Start-Isolated([string]$exe,[string]$dir,[string[]]$argv,[string]$tag){
    if(!(Test-Path $dir)){$null=New-Item -ItemType Directory -Path $dir}
    $p=Start-Process -FilePath $exe -ArgumentList $argv -WorkingDirectory $dir -RedirectStandardOutput "$root\$tag.out.log" -RedirectStandardError "$root\$tag.err.log" -PassThru -NoNewWindow
    $procs.Add($p)
    return $p
}
function Wait-Listener([System.Diagnostics.Process]$p,[string]$addr,[int]$port){
    for($i=0;$i -lt 100;$i++){
        $p.Refresh()
        if($p.HasExited){throw "Test server exited: $($p.ExitCode)"}
        $c=[Net.Sockets.TcpClient]::new()
        try{
            $task=$c.ConnectAsync($addr,$port)
            if($task.Wait(100) -and $c.Connected){return}
        }catch{}finally{$c.Dispose()}
        Start-Sleep -Milliseconds 100
    }
    throw 'Listener did not start'
}
function Stop-Owned([System.Diagnostics.Process]$p){
    $p.Refresh()
    if(!$p.HasExited){$p.Kill();if(!$p.WaitForExit(10000)){throw 'Test process failed to stop'}}
}
function Run-Ctl([string[]]$argv,[int]$expected,[string]$tag){
    $p=Start-Process -FilePath "$bin\bk-remote-relayctl.exe" -ArgumentList $argv -WorkingDirectory $root -RedirectStandardOutput "$root\$tag.json" -RedirectStandardError "$root\$tag.err.log" -Wait -PassThru -NoNewWindow
    if($p.ExitCode -ne $expected){Get-Content "$root\$tag.err.log" -Tail 5;Get-Content "$root\$tag.json" -Tail 5;throw "$tag expected exit $expected got $($p.ExitCode)"}
    if((Get-Item "$root\$tag.json").Length -gt 0){return Get-Content "$root\$tag.json" -Raw}
    return ''
}
function Raw-Console([int]$port,[string]$command){
    $c=[Net.Sockets.TcpClient]::new()
    try{
        $c.ReceiveTimeout=4000;$c.SendTimeout=4000;$c.Connect($loop,$port)
        $s=$c.GetStream();$buf=[Text.Encoding]::UTF8.GetBytes($command);$s.Write($buf,0,$buf.Length)
        $ms=[IO.MemoryStream]::new();$chunk=New-Object byte[] 4096
        do{$n=$s.Read($chunk,0,$chunk.Length);if($n -gt 0){$ms.Write($chunk,0,$n)}}while($n -gt 0 -and $ms.Length -lt 16384)
        return [Text.Encoding]::UTF8.GetString($ms.ToArray()).Trim()
    }finally{$c.Dispose()}
}
function Assert-State($raw,[int]$version,[string]$state,[string]$node){
    $x=$raw|ConvertFrom-Json
    if(!$x.ok -or $x.data.journal.current.revision -ne $version -or $x.data.runtime.state -ne $state){throw "State mismatch: $raw"}
    $eligible=@($x.data.runtime.eligible)
    if($node){if($eligible.Count -ne 1 -or $eligible[0] -ne $node){throw 'Eligible node mismatch'}}
    elseif($eligible.Count -ne 0){throw 'Expected no eligible nodes'}
}
try{
    $pa=Free-Group $ip @(0,2)
    $pb=Free-Group $ip @(0,2)
    while([math]::Abs($pa-$pb) -le 2){$pb=Free-Group $ip @(0,2)}
    $ps=Free-Group $loop @(-1,0,2)
    $console=$ps-1
    $a=('{0}:{1}' -f $ip,$pa);$b=('{0}:{1}' -f $ip,$pb)
    $keyBytes=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($keyBytes)}finally{$rng.Dispose()}
    $key=[Convert]::ToBase64String($keyBytes)
    $db="$root\pool.sqlite3";$token="$root\admin.token";$bad="$root\wrong.token"
    $null=Run-Ctl @('init-config',$db,$a) 0 'init-config'
    $null=Run-Ctl @('init-token',$token) 0 'init-token'
    $null=Run-Ctl @('init-token',$bad) 0 'wrong-token'
    $ra=Start-Isolated "$bin\hbbr.exe" "$root\relay-a" @('-b',$ip,'-p',"$pa",'-k',$key) 'relay-a'
    $rb=Start-Isolated "$bin\hbbr.exe" "$root\relay-b" @('-b',$ip,'-p',"$pb",'-k',$key) 'relay-b'
    Wait-Listener $ra $ip $pa;Wait-Listener $rb $ip $pb
    $serverArgs=@('-b',$loop,'-p',"$ps",'-k',$key,'--bk-relay-pool',$db,'--bk-relay-admin-token-file',$token)
    $hbbs=Start-Isolated "$bin\hbbs.exe" "$root\hbbs" $serverArgs 'hbbs'
    Wait-Listener $hbbs $loop $console
    $admin=@('admin',"$console",$token)
    $raw=Run-Ctl ($admin+@('status')) 0 'status-a'
    Assert-State $raw 1 'healthy' $a
    if((Raw-Console $console 'tg 192.0.2.1 192.0.2.2') -ne ('"'+$a+'"')){throw 'Native routing did not select A'}
    'E2E_INITIAL_NATIVE_SELECTION_PASS'
    $null=Run-Ctl @('admin',"$console",$bad,'status') 1 'wrong-auth'
    if((Raw-Console $console "rs $b") -notmatch 'Managed relay mode'){throw 'Legacy rs mutation not blocked'}
    if((Raw-Console $console 'aur Y') -notmatch 'Managed relay mode'){throw 'Legacy aur mutation not blocked'}
    'E2E_ADMIN_AUTH_AND_LEGACY_GUARD_PASS'
    $raw=Run-Ctl ($admin+@('publish','1',$b)) 0 'publish-b'
    Assert-State $raw 2 'healthy' $b
    if((Raw-Console $console 'tg 192.0.2.1 192.0.2.2') -ne ('"'+$b+'"')){throw 'Native routing did not select B'}
    $null=Run-Ctl ($admin+@('publish','1',$a)) 1 'stale-version'
    'E2E_NATIVE_SWITCH_AND_CAS_PASS'
    Stop-Owned $rb
    $raw=Run-Ctl ($admin+@('refresh')) 0 'all-down'
    Assert-State $raw 2 'unavailable' ''
    if((Raw-Console $console 'tg 192.0.2.1 192.0.2.2') -ne '""'){throw 'Failed relay still assigned'}
    $null=Run-Ctl ($admin+@('publish','2',$b)) 1 'reject-down'
    'E2E_ALL_DOWN_FAIL_CLOSED_PASS'
    $raw=Run-Ctl ($admin+@('rollback','2')) 0 'rollback-a'
    Assert-State $raw 3 'healthy' $a
    if((Raw-Console $console 'tg 192.0.2.1 192.0.2.2') -ne ('"'+$a+'"')){throw 'Native rollback not applied'}
    'E2E_ROLLBACK_PASS'
    Stop-Owned $hbbs
    $hbbs=Start-Isolated "$bin\hbbs.exe" "$root\hbbs" $serverArgs 'hbbs-restart'
    Wait-Listener $hbbs $loop $console
    $raw=Run-Ctl ($admin+@('status')) 0 'restart-status'
    Assert-State $raw 3 'healthy' $a
    if((Raw-Console $console 'tg 192.0.2.1 192.0.2.2') -ne ('"'+$a+'"')){throw 'Restart runtime mismatch'}
    'E2E_RESTART_PERSISTENCE_PASS'
    Stop-Owned $hbbs
    $legacy=Start-Isolated "$bin\hbbs.exe" "$root\legacy" @('-b',$loop,'-p',"$ps",'-k',$key,'-r',$a) 'legacy'
    Wait-Listener $legacy $loop $console
    if((Raw-Console $console 'rs') -ne $a){throw 'Legacy mode changed'}
    'E2E_NATIVE_LEGACY_MODE_PASS'
    if($oldDb -and (Get-FileHash $repoDb).Hash -ne $oldDb){throw 'Existing database changed'}
    'SERVER_EXISTING_DB_UNCHANGED'
    'MANAGED_RELAY_E2E_PASS'
}finally{
    foreach($p in $procs){Stop-Owned $p}
    'ISOLATED_TEST_PROCESSES_STOPPED'
}
