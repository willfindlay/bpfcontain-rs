Vagrant.configure("2") do |config|
    config.vm.box = "archlinux/archlinux"

    config.vm.define 'arch'

    config.vm.synced_folder ".", "/vagrant"

    config.ssh.extra_args = ["-t", "cd /vagrant; bash --login"]
end
