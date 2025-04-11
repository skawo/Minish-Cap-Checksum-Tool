using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace ZeldaMCSaveCheck
{
    public partial class Form1 : Form
    {
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;
        const int PAGE_READWRITE = 0x04;
        const int PROCESS_WM_READ = 0x0010;

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }


        string filePath = "";
        DateTime lastSave;
        Timer s;
        Timer w;
        int saveAddr;

        public Form1()
        {
            InitializeComponent();
            button2.Enabled = false;
        }

        private void W_Tick(object sender, EventArgs e)
        {
            w.Stop();

            Process process = Process.GetProcessesByName("mGBA")[0];
            IntPtr processHandle = OpenProcess(PROCESS_WM_READ, false, process.Id);

            int bytesRead = 0;
            byte[] buffer = new byte[0x500];

            ReadProcessMemory((int)processHandle, saveAddr, buffer, buffer.Length, ref bytesRead);

            List<byte> type = new List<byte>() { (byte)'3', (byte)'Z', (byte)'C', (byte)'M' };

            int ch = Checksum(type);
            int ch2z = Checksum(buffer.ToList());
            int fzz = Finalize(ch, ch2z);

            this.label1.Invoke((MethodInvoker)delegate
            {
                label1.Text = (fzz & 0xFFFF).ToString("X4");

                if ((fzz & 0xFFFF) == 0)
                    label1.ForeColor = Color.Red;
                else
                    label1.ForeColor = Color.Black;

                label1.BackColor = label1.BackColor;

            });

            this.label2.Invoke((MethodInvoker)delegate
            {
                string t = (fzz & 0xFFFF0000).ToString("X8");

                if (t.Length > 4)
                {
                    label2.Text = t.Substring(0, 4);
                }
                else
                    label2.Text = "0000";


            });



            w.Start();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog of = new OpenFileDialog();

            if (of.ShowDialog() == DialogResult.OK)
            {
                filePath = of.FileName;

                s = new Timer();
                s.Interval = 100;
                s.Tick += S_Tick;
                s.Start();
            }

        }

        private DateTime GetLastWriteTimeForFile(string Filename)
        {
            try
            {
                if (File.Exists(Filename))
                {
                    return File.GetLastWriteTime(Filename);
                }
                else
                    return new DateTime();
            }
            catch (Exception)
            {
                return new DateTime();
            }
        }

        private void S_Tick(object sender, EventArgs e)
        {
            s.Stop();

            DateTime cur = GetLastWriteTimeForFile(filePath);

            if (cur != lastSave)
            {
                lastSave = cur;

                if (File.Exists("out"))
                    File.Delete("out");

                File.Copy(filePath, "out");

                byte[] b = File.ReadAllBytes("out");
                List<byte> outb = new List<byte>();

                byte[] buffer = new byte[8];
                long position = 0;

                using (MemoryStream input = new MemoryStream(b))
                {
                    while (position < b.Length)
                    {
                        input.Read(buffer, 0, buffer.Length);
                        Array.Reverse(buffer);
                        outb.AddRange(buffer);
                        position += 8;
                    }
                }

                outb = outb.Skip(0x80).Take(0x500).ToList();
                List<byte> type = new List<byte>() { (byte)'3', (byte)'Z', (byte)'C', (byte)'M' };

                int ch = Checksum(type);
                int ch2z = Checksum(outb);
                int fzz = Finalize(ch, ch2z);

                File.Delete("out");

                this.label1.Invoke((MethodInvoker)delegate
                {
                    label1.Text = (fzz & 0xFFFF).ToString("X4");

                    if ((fzz & 0xFFFF) == 0)
                        label1.ForeColor = Color.Red;
                    else
                        label1.ForeColor = Color.Black;

                    label1.BackColor = label1.BackColor;

                });

                this.label2.Invoke((MethodInvoker)delegate
                {
                    string t = (fzz & 0xFFFF0000).ToString("X8");

                    if (t.Length > 4)
                    {
                        label2.Text = t.Substring(0, 4);
                    }
                    else
                        label2.Text = "0000";


                });

            }

            s.Start();
        }

        static int Checksum(List<byte> data)
        {
            int pos = 0;

            int i = data.Count;
            int sum = 0;

            while (i > 0)
            {
                sum += (data[pos] | data[pos + 1] << 8) ^ i;
                pos += 2;
                i -= 2;
            }

            return sum & 0xFFFF;
        }

        static int Finalize(int ch1, int ch2)
        {
            int f = (ch1 + ch2) & 0xFFFF;
            int result = f << 16;
            int s = ~f & 0xFFFF;
            s += 1;
            return result + s;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            // getting minimum & maximum address
            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            IntPtr proc_min_address = sys_info.minimumApplicationAddress;
            IntPtr proc_max_address = sys_info.maximumApplicationAddress;

            // saving the values as long ints so I won't have to do a lot of casts later
            long proc_min_address_l = (long)proc_min_address;
            long proc_max_address_l = (long)proc_max_address;

            Process[] procs = Process.GetProcessesByName("mGBA");

            if (procs.Length != 1)
            {
                MessageBox.Show("Did not find mGBA Process, or more than one process is running...");
                return;
            }

            Process process = procs[0];
            saveAddr = 0;

            // opening the process with desired access level
            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);

            // this will store any information we get from VirtualQueryEx()
            MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

            int bytesRead = 0;  // number of bytes read with ReadProcessMemory

            while (proc_min_address_l < proc_max_address_l)
            {
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);

                // if this memory chunk is accessible
                if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                {
                    byte[] buffer = new byte[mem_basic_info.RegionSize];
                    // read everything in the buffer above
                    ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);

                    string text = Encoding.UTF8.GetString(buffer);

                    if (text.Contains(textBox2.Text))
                    {
                        int index = text.IndexOf(textBox2.Text);

                        byte[] buf2 = new byte[0x500];
                        ReadProcessMemory((int)processHandle, (int)proc_min_address_l + index - 0x80, buf2, buf2.Length, ref bytesRead);

                        if ((buf2[0] == 0) && (buf2[1] == 1) && (buf2[2] == 1) && (buf2[3] == 1))
                        {
                            saveAddr = (int)proc_min_address_l + index - 0x80;
                            break;
                        }
                    }
                }

                // move to the next memory chunk
                proc_min_address_l += mem_basic_info.RegionSize;
                proc_min_address = new IntPtr(proc_min_address_l);
            }

            if (saveAddr == 0)
            {
                MessageBox.Show("Save not found in memory...");
                return;
            }

            button2.Enabled = false;
            button1.Enabled = false;

            w = new Timer();
            w.Interval = 100;
            w.Tick += W_Tick;
            w.Start();


        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {
            if (String.IsNullOrWhiteSpace(textBox2.Text))
            {
                button1.Enabled = true;
                button2.Enabled = false;
            }
            else
            {
                button1.Enabled = false;
                button2.Enabled = true;
            }
        }
    }
}