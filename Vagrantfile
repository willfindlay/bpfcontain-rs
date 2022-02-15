Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2110"
  config.vm.define 'bpfcontain-ci'

  # Allocate more memory for tests
  config.vm.provider :virtualbox do |v|
    v.memory = 4096
  end
  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 4096
  end

  # Sync the project to /vagrant
  config.vm.synced_folder ".", "/vagrant", type: "rsync", rsync__exclude: ['.git/', 'target/']

  # Set up the environment
  config.vm.provision "shell" do |s|
    # Do a system upgrade and install required tooling
    s.inline = "
      if ! grep -q \"cd /vagrant\" /etc/profile ; then
          echo \"cd /vagrant\" >> /etc/profile
      fi

      export DEBIAN_FRONTEND=noninteractive

      # system upgrade
      apt-get -y update
      apt-get -y upgrade

      # install rust
      su vagrant <<-EOF
curl https://sh.rustup.rs -sSf | sh -s -- -y
source \\$HOME/.cargo/env
rustup default nightly
EOF

      # install needed packages
      apt-get install -y gcc clang linux-tools-generic make libelf-dev gcc-multilib ca-certificates curl gnupg lsb-release

      # install docker
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
      echo \"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\" | tee /etc/apt/sources.list.d/docker.list > /dev/null
      apt-get -y update
      apt-get -y install docker-ce docker-ce-cli containerd.io
      usermod -a -G docker vagrant

      sed -i 's/GRUB_CMDLINE_LINUX=\"\"/GRUB_CMDLINE_LINUX=\"lsm=lockdown,yama,bpf\"/' /etc/default/grub
      update-grub

      reboot
    "
  end
end
