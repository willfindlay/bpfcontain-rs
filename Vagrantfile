Vagrant.configure("2") do |config|
  # Use Arch Linux as the base for the box
  config.vm.box = "archlinux/archlinux"
  config.vm.define 'arch'

  # Sync the project to /vagrant
  config.vm.synced_folder ".", "/vagrant", type: "rsync", rsync__exclude: '.git/'

  # Set up the environment
  config.vm.provision "shell" do |s|
    # Do a system upgrade and install required tooling
    s.inline = "
      if ! grep -q \"cd /vagrant\" /etc/profile ; then
          echo \"cd /vagrant\" >> /etc/profile
      fi

      sudo pacman --noconfirm -Syu
      sudo pacman --noconfirm -S rust clang make libelf bpf libbpf

      cargo install libbpf-cargo --root /home/vagrant/.cargo
      chown -R vagrant:vagrant /home/vagrant/.cargo
    "
  end
end
