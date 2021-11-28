function Get-DomainSID {
    param(
        [String]
        $Domain
    )

    $FoundDomain = Get-NetDomain -Domain $Domain

    if($FoundDomain) {
        $PrimaryDC = $FoundDomain.PdcRoleOwner
        $PrimaryDCSID = (Get-NetComputer -Domain $Domain -ComputerName $PrimaryDC -FullData).objectsid
        $Parts = $PrimaryDCSID.split("-")
        $Parts[0..($Parts.length -2)] -join "-"
    }
}

function Add-Win32Type
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function struct
{


    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    ForEach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    ForEach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}

function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function Convert-LDAPProperty {
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}

function New-InMemoryModule
{

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    ForEach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

function psenum
{

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    ForEach ($Key in $EnumElements.Keys)
    {
        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

$Mod = New-InMemoryModule -ModuleName Win32

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr]))
)

$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']

function Get-NetDomain {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain
    )

    process {
        if($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}


function Get-DomainSearcher {
    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)]
        [Int]
        $PageSize = 200
    )

    if(!$Domain) {
        $Domain = (Get-NetDomain).name
    }
    else {
        if(!$DomainController) {
            try {
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController + "/"
    }
    if($ADSprefix) {
        $SearchString += $ADSprefix + ","
    }

    if($ADSpath) {
        if($ADSpath -like "GC://*") {
            $DistinguishedName = $AdsPath
            $SearchString = ""
        }
        else {
            if($ADSpath -like "LDAP://*") {
                $ADSpath = $ADSpath.Substring(7)
            }
            $DistinguishedName = $ADSpath
        }
    }
    else {
        $DistinguishedName = "DC=$($Domain.Replace('.', ',DC='))"
    }

    $SearchString += $DistinguishedName
    Write-Verbose "Get-DomainSearcher search string: $SearchString"

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $Searcher.PageSize = $PageSize
    $Searcher
}

function Get-NetUser {

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Switch]
        $Unconstrained,

        [Switch]
        $AllowDelegation,

        [ValidateRange(1,10000)]
        [Int]
        $PageSize = 200
    )

    begin {
        $UserSearcher = Get-DomainSearcher -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize
    }

    process {
        if($UserSearcher) {

            if($Unconstrained) {
                Write-Verbose "Checking for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($AllowDelegation) {
                Write-Verbose "Checking for users who can be delegated"
                $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
            }
            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            if($UserName) {
                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName)$Filter)"
            }
            elseif($SPN) {
                $UserSearcher.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$Filter)"
            }
            else {
                $UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
            }

            $UserSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                Convert-LDAPProperty -Properties $_.Properties
            }
        }
    }
}

function Get-DomainSID {
    param(
        [String]
        $Domain
    )

    $FoundDomain = Get-NetDomain -Domain $Domain

    if($FoundDomain) {
        $PrimaryDC = $FoundDomain.PdcRoleOwner
        $PrimaryDCSID = (Get-NetComputer -Domain $Domain -ComputerName $PrimaryDC -FullData).objectsid
        $Parts = $PrimaryDCSID.split("-")
        $Parts[0..($Parts.length -2)] -join "-"
    }
}

function Get-NetComputer {

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',

        [String]
        $SPN,

        [String]
        $OperatingSystem,

        [String]
        $ServicePack,

        [String]
        $Filter,

        [Switch]
        $Printers,

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)]
        [Int]
        $PageSize = 200
    )

    begin {
        $CompSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    process {

        if ($CompSearcher) {

            if($Unconstrained) {
                Write-Verbose "Searching for computers with for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($Printers) {
                Write-Verbose "Searching for printers"
                $Filter += "(objectCategory=printQueue)"
            }
            if($SPN) {
                Write-Verbose "Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if($OperatingSystem) {
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if($ServicePack) {
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }

            $CompSearcher.filter = "(&(sAMAccountType=805306369)(dnshostname=$ComputerName)$Filter)"

            try {

                $CompSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Up = $True
                    if($Ping) {
                        $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if($Up) {
                        if ($FullData) {
                            Convert-LDAPProperty -Properties $_.Properties
                        }
                        else {
                            $_.properties.dnshostname
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}


function Get-NetGroup {
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline=$True)]
    [String]
    $GroupName = '*',

    [String]
    $SID,

    [String]
    $UserName,

    [String]
    $Filter,

    [String]
    $Domain,

    [String]
    $DomainController,

    [String]
    $ADSpath,

    [Switch]
    $AdminCount,

    [Switch]
    $FullData,

    [Switch]
    $RawSids,

    [ValidateRange(1,10000)]
    [Int]
    $PageSize = 200
)

begin {
    $GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
}

process {
    if($GroupSearcher) {

        if($AdminCount) {
            Write-Verbose "Checking for adminCount=1"
            $Filter += "(admincount=1)"
        }

        if ($UserName) {
            $User = Get-ADObject -SamAccountName $UserName -Domain $Domain -DomainController $DomainController -ReturnRaw -PageSize $PageSize

            $UserDirectoryEntry = $User.GetDirectoryEntry()

            $UserDirectoryEntry.RefreshCache("tokenGroups")

            $UserDirectoryEntry.TokenGroups | Foreach-Object {
                $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value

                if(!($GroupSid -match '^S-1-5-32-545|-513$')) {
                    if($FullData) {
                        Get-ADObject -SID $GroupSid -PageSize $PageSize
                    }
                    else {
                        if($RawSids) {
                            $GroupSid
                        }
                        else {
                            Convert-SidToName $GroupSid
                        }
                    }
                }
            }
        }
        else {
            if ($SID) {
                $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
            }
            else {
                $GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
            }

            $GroupSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                if ($FullData) {
                    Convert-LDAPProperty -Properties $_.Properties
                }
                else {
                    $_.properties.samaccountname
                }
            }
        }
    }
}
}

function Get-NetGroupMember {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName,

        [String]
        $SID,

        [String]
        $Domain = (Get-NetDomain).Name,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [Switch]
        $Recurse,

        [Switch]
        $UseMatchingRule,

        [ValidateRange(1,10000)]
        [Int]
        $PageSize = 200
    )

    begin {
        $GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if(!$DomainController) {
            $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
        }
    }

    process {

        if ($GroupSearcher) {

            if ($Recurse -and $UseMatchingRule) {
                if ($GroupName) {
                    $Group = Get-NetGroup -GroupName $GroupName -Domain $Domain -FullData -PageSize $PageSize
                }
                elseif ($SID) {
                    $Group = Get-NetGroup -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                else {
                    $SID = (Get-DomainSID -Domain $Domain) + "-512"
                    $Group = Get-NetGroup -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                $GroupDN = $Group.distinguishedname
                $GroupFoundName = $Group.name

                if ($GroupDN) {
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupDN)$Filter)"
                    $GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName','samaccounttype','lastlogon','lastlogontimestamp','dscorepropagationdata','objectsid','whencreated','badpasswordtime','accountexpires','iscriticalsystemobject','name','usnchanged','objectcategory','description','codepage','instancetype','countrycode','distinguishedname','cn','admincount','logonhours','objectclass','logoncount','usncreated','useraccountcontrol','objectguid','primarygroupid','lastlogoff','samaccountname','badpwdcount','whenchanged','memberof','pwdlastset','adspath'))

                    $Members = $GroupSearcher.FindAll()
                    $GroupFoundName = $GroupName
                }
                else {
                    Write-Error "Unable to find Group"
                }
            }
            else {
                if ($GroupName) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
                }
                elseif ($SID) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }
                else {
                    $SID = (Get-DomainSID -Domain $Domain) + "-512"
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }

                $GroupSearcher.FindAll() | ForEach-Object {
                    try {
                        if (!($_) -or !($_.properties) -or !($_.properties.name)) { continue }

                        $GroupFoundName = $_.properties.name[0]
                        $Members = @()

                        if ($_.properties.member.Count -eq 0) {
                            $Finished = $False
                            $Bottom = 0
                            $Top = 0
                            while(!$Finished) {
                                $Top = $Bottom + 1499
                                $MemberRange="member;range=$Bottom-$Top"
                                $Bottom += 1500
                                $GroupSearcher.PropertiesToLoad.Clear()
                                [void]$GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                                try {
                                    $Result = $GroupSearcher.FindOne()
                                    if ($Result) {
                                        $RangedProperty = $_.Properties.PropertyNames -like "member;range=*"
                                        $Results = $_.Properties.item($RangedProperty)
                                        if ($Results.count -eq 0) {
                                            $Finished = $True
                                        }
                                        else {
                                            $Results | ForEach-Object {
                                                $Members += $_
                                            }
                                        }
                                    }
                                    else {
                                        $Finished = $True
                                    }
                                }
                                catch [System.Management.Automation.MethodInvocationException] {
                                    $Finished = $True
                                }
                            }
                        }
                        else {
                            $Members = $_.properties.member
                        }
                    }
                    catch {
                        Write-Verbose $_
                    }
                }
            }

            $Members | Where-Object {$_} | ForEach-Object {
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                }
                else {
                    if($DomainController) {
                        $Result = [adsi]"LDAP://$DomainController/$_"
                    }
                    else {
                        $Result = [adsi]"LDAP://$_"
                    }
                    if($Result){
                        $Properties = $Result.Properties
                    }
                }

                if($Properties) {

                    if($Properties.samaccounttype -notmatch '805306368') {
                        $IsGroup = $True
                    }
                    else {
                        $IsGroup = $False
                    }

                    if ($FullData) {
                        $GroupMember = Convert-LDAPProperty -Properties $Properties
                    }
                    else {
                        $GroupMember = New-Object PSObject
                    }

                    $GroupMember | Add-Member Noteproperty 'GroupDomain' $Domain
                    $GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName

                    try {
                        $MemberDN = $Properties.distinguishedname[0]

                        $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        $MemberName = $Properties.samaccountname[0]
                    }
                    else {
                        try {
                            $MemberName = Convert-SidToName $Properties.cn[0]
                        }
                        catch {
                            $MemberName = $Properties.cn
                        }
                    }

                    if($Properties.objectSid) {
                        $MemberSid = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectSid[0],0).Value)
                    }
                    else {
                        $MemberSid = $Null
                    }

                    $GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $GroupMember | Add-Member Noteproperty 'MemberSid' $MemberSid
                    $GroupMember | Add-Member Noteproperty 'IsGroup' $IsGroup
                    $GroupMember | Add-Member Noteproperty 'MemberDN' $MemberDN
                    $GroupMember

                    if ($Recurse -and !$UseMatchingRule -and $IsGroup -and $MemberName) {
                        Get-NetGroupMember -FullData -Domain $MemberDomain -DomainController $DomainController -GroupName $MemberName -Recurse -PageSize $PageSize
                    }
                }

            }
        }
    }
    }

function Get-NetShare {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost'
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        $ComputerName = Get-NameField -Object $ComputerName

        $QueryLevel = 1
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        $Result = $Netapi32::NetShareEnum($ComputerName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

        $Offset = $PtrInfo.ToInt64()

        Write-Debug "Get-NetShare result: $Result"

        if (($Result -eq 0) -and ($Offset -gt 0)) {

            $Increment = $SHARE_INFO_1::GetSize()

            for ($i = 0; ($i -lt $EntriesRead); $i++) {
                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $SHARE_INFO_1
                $Info | Select-Object *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment
            }

            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug 'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
    }


function Get-NameField {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        $Object
    )
    process {
        if($Object) {
            if ( [bool]($Object.PSobject.Properties.name -match "dnshostname") ) {
                $Object.dnshostname
            }
            elseif ( [bool]($Object.PSobject.Properties.name -match "name") ) {
                $Object.name
            }
            else {
                $Object
            }
        }
        else {
            return $Null
        }
    }
    }

function Invoke-ShareFinder {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $ExcludeStandard,

        [Switch]
        $ExcludePrint,

        [Switch]
        $ExcludeIPC,

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $SearchForest,

        [ValidateRange(1,100)]
        [Int]
        $Threads
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running with delay of $Delay"

        [String[]] $ExcludedShares = @('')

        if(!$ComputerName) {

            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                $TargetDomains = Get-NetForestDomain | ForEach-Object { $_.Name }
            }
            else {
                $TargetDomains = @( (Get-NetDomain).name )
            }

            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }
            else {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose "[*] Querying domain $Domain for hosts"
                    $ComputerName += Get-NetComputer -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
                }
            }

            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.count) -eq 0) {
                throw "No hosts found!"
            }
        }

        $HostEnumBlock = {
            param($ComputerName, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)

            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                $Shares = Get-NetShare -ComputerName $ComputerName
                ForEach ($Share in $Shares) {
                    Write-Debug "[*] Server share: $Share"
                    $NetName = $Share.shi1_netname
                    $Remark = $Share.shi1_remark
                    $Path = '\\'+$ComputerName+'\'+$NetName

                    if (($NetName) -and ($NetName.trim() -ne '')) {
                        if($CheckAdmin) {
                            if($NetName.ToUpper() -eq "ADMIN$") {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    "\\$ComputerName\$NetName `t- $Remark"
                                }
                                catch {
                                    Write-Debug "Error accessing path $Path : $_"
                                }
                            }
                        }
                        elseif ($ExcludedShares -NotContains $NetName.ToUpper()) {
                            if($CheckShareAccess) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    "\\$ComputerName\$NetName `t- $Remark"
                                }
                                catch {
                                    Write-Debug "Error accessing path $Path : $_"
                                }
                            }
                            else {
                                "\\$ComputerName\$NetName `t- $Remark"
                            }
                        }
                    }
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"

            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'CheckShareAccess' = $CheckShareAccess
                'ExcludedShares' = $ExcludedShares
                'CheckAdmin' = $CheckAdmin
            }

            Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] active hosts: $($ComputerName.count)"
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1

                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] server $Computer ($Counter of $($ComputerName.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $CheckShareAccess, $ExcludedShares, $CheckAdmin
            }
        }

    }
}

function Invoke-ThreadedFunction {
# Helper used by any threaded host enumeration functions
[CmdletBinding()]
param(
    [Parameter(Position=0,Mandatory=$True)]
    [String[]]
    $ComputerName,

    [Parameter(Position=1,Mandatory=$True)]
    [System.Management.Automation.ScriptBlock]
    $ScriptBlock,

    [Parameter(Position=2)]
    [Hashtable]
    $ScriptParameters,

    [Int]
    $Threads = 20,

    [Switch]
    $NoImports
)

begin {

    if ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    Write-Verbose "[*] hosts: $($ComputerName.count)"

    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

    if(!$NoImports) {

        $MyVars = Get-Variable -Scope 2

        $VorbiddenVars = @("")

        ForEach($Var in $MyVars) {
            if($VorbiddenVars -NotContains $Var.Name) {
            $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }

        ForEach($Function in (Get-ChildItem Function:)) {
            $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
        }
    }

    $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
    $Pool.Open()

    $Jobs = @()
    $PS = @()
    $Wait = @()

    $Counter = 0
}

process {

    ForEach ($Computer in $ComputerName) {

        if ($Computer -ne '') {
            While ($($Pool.GetAvailableRunspaces()) -le 0) {
                Start-Sleep -MilliSeconds 500
            }

            $PS += [powershell]::create()

            $PS[$Counter].runspacepool = $Pool

            $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter('ComputerName', $Computer)
            if($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                }
            }

            $Jobs += $PS[$Counter].BeginInvoke();

            $Wait += $Jobs[$Counter].AsyncWaitHandle
        }
        $Counter = $Counter + 1
    }
}

end {

    Write-Verbose "Waiting for scanning threads to finish..."

    $WaitTimeout = Get-Date

    while ($($Jobs | Where-Object {$_.IsCompleted -eq $False}).count -gt 0 -or $($($(Get-Date) - $WaitTimeout).totalSeconds) -gt 60) {
            Start-Sleep -MilliSeconds 500
        }

    for ($y = 0; $y -lt $Counter; $y++) {

        try {
            $PS[$y].EndInvoke($Jobs[$y])

        } catch {
            Write-Warning "error: $_"
        }
        finally {
            $PS[$y].Dispose()
        }
    }

    $Pool.Dispose()
    Write-Verbose "All threads completed!"
}
}
