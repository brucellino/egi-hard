# encoding: utf-8
# copyright: 2018, The Authors

title 'EGI-SVG-CVE-2018-8897'

# you add controls here
control 'EGI-SVG-CVE-2018-8897' do
  impact 0.7
  title 'CVE IDs CVE-2018-8897 CVE-2018-1087 CVE-2017-16939'
  desc 'Linux Kernel vulnerabilities. kernel exception handling can allow an unprivileged user to crash the system and cause a Denial of Service (DoS) (CVE-2018-8897). \n
            A  vulnerability concerning the Linux kernels KVM hypervisor exception handling can allow an unprivileged KVM guest user to crash the guest or, potentially, escalate their privileges in the guest (CVE-2018-1087). \n
            The use-after-free vulnerability flaw in XFRM mentioned in a previous alert [EGI-SVG-CVE-2017-16939] can, in some circumstances, lead to privilege escalation. '
  
  describe command('uname -r') do
    its('stdout') { should cmp > "3.10.0-862" }
  end
end
