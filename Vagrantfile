Vagrant.configure("2") do |config|
  # Use Arch Linux as the base for the box
  config.vm.box = "archlinux/archlinux"
  config.vm.define 'arch'

  # Sync the project to /vagrant
  config.vm.synced_folder ".", "/vagrant"

  # Start ssh sessions in /vagrant
  config.ssh.extra_args = ["-t", "cd /vagrant; bash --login"]

  # Set up the environment
  config.vm.provision "shell" do |s|
    s.inline = "
      sudo pacman --noconfirm -Syu
      sudo pacman --noconfirm -S rust clang make libelf bpf libbpf
      cargo install libbpf-cargo
    "
  end

  # Reload to boot into a fresh kernel
  config.vm.provision :reload
end
