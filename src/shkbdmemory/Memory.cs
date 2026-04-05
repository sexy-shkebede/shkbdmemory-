using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Globalization;

namespace shkbdmemory;

public unsafe class Memory : IDisposable
{
    private IntPtr _processHandle;
    public Process TargetProcess { get; }
    public IntPtr ModuleBase { get; }

    public Memory(string processName)
    {
        var processes = Process.GetProcessesByName(processName);
        if (processes.Length == 0) throw new Exception("Process not found");
        
        TargetProcess = processes[0];
        ModuleBase = TargetProcess.MainModule.BaseAddress;
        _processHandle = OpenProcess(0x1F0FFF, false, TargetProcess.Id);
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int id);
    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr h, IntPtr adr, byte[] buf, int sz, out int rd);
    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr h, IntPtr adr, byte[] buf, int sz, out int wr);
    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtectEx(IntPtr h, IntPtr adr, uint sz, uint newProt, out uint oldProt);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    public T Read<T>(IntPtr address) where T : unmanaged
    {
        int size = sizeof(T);
        byte[] buffer = new byte[size];
        ReadProcessMemory(_processHandle, address, buffer, size, out _);
        fixed (byte* p = buffer) return *(T*)p;
    }

    public void Write<T>(IntPtr address, T value) where T : unmanaged
    {
        int size = sizeof(T);
        byte[] buffer = new byte[size];
        fixed (byte* p = buffer) *(T*)p = value;
        VirtualProtectEx(_processHandle, address, (uint)size, 0x40, out uint old);
        WriteProcessMemory(_processHandle, address, buffer, size, out _);
        VirtualProtectEx(_processHandle, address, (uint)size, old, out _);
    }

    public IntPtr Scan(string pattern)
    {
        var module = TargetProcess.MainModule;
        byte[] data = new byte[module.ModuleMemorySize];
        ReadProcessMemory(_processHandle, ModuleBase, data, data.Length, out _);
        string[] parts = pattern.Split(' ');
        byte?[] patternBytes = parts.Select(x => (x == "??" || x == "?") ? (byte?)null : byte.Parse(x, NumberStyles.HexNumber)).ToArray();
        for (int i = 0; i < data.Length - patternBytes.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < patternBytes.Length; j++)
            {
                if (patternBytes[j].HasValue && data[i + j] != patternBytes[j])
                {
                    found = false;
                    break;
                }
            }
            if (found) return ModuleBase + i;
        }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        if (_processHandle != IntPtr.Zero) CloseHandle(_processHandle);
    }
}
