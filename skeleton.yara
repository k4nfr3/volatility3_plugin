rule Skeleton_Key
{
    strings:
        $skeleton_Key_Hash = { 9A 00 00 C0 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? }
    condition:
        $skeleton_Key_Hash  
}