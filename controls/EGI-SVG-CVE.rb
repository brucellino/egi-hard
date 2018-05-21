# encoding: utf-8
# copyright: 2018, The Authors

title 'EGI-SVG-CVE-2018-8897'

# you add controls here
control 'EGI-SVG-CVE-2018-8897' do
  impact 0.59
  title 'CVE IDs CVE-2018-8897 CVE-2018-1087 CVE-2017-16939'
  desc 'Linux Kernel vulnerabilities. kernel exception handling can allow an\n
            unprivileged user to crash the system and cause a Denial of Service (DoS)\n
            (CVE-2018-8897). \n
            A  vulnerability concerning the Linux kernels KVM hypervisor exception\n
            handling can allow an unprivileged KVM guest user to crash the guest or, potentially, escalate their privileges in the guest (CVE-2018-1087). \n
            The use-after-free vulnerability flaw in XFRM mentioned in a previous alert [EGI-SVG-CVE-2017-16939] can, in some circumstances, lead to privilege escalation. '

  case os.name
  when (cmp = "redhat" or cmp = "centos") then
    puts "It's a RedHat Daddy"
    describe package('kernel') do
      its('version') { should cmp > "4"}
    end
    describe package('linux-kvm') do
      its('version') { should cmp > "4" }
    end
  when cmp = "debian" then
    describe package('linux') do
      its('version') { should cmp > "4"}
    end
  when cmp = "ubuntu" then
    describe package('linux') do
      its('version') { should cmp > '4' }
    end
  else
    puts "It's a #{os.name} Daddy, we can't deal with that"
  end
end

control 'CVE-2017-16939 Singularity setuid' do
  title 'Singluarity SetUID'
  desc 'Singluarity Setup'
  impact 0.81

  describe package('')
end
