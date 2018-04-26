# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|
  config.vm.provider "virtualbox" do |v|
    v.memory = 512
    v.cpus = 1
  end
  config.vm.box = "debian/contrib-jessie64"
  config.vm.provision "shell", inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y tcpdump
  SHELL

  config.vm.define "netflow" do |node|
    node.vm.hostname = "netflow"
    node.vm.network "private_network", ip: "10.0.0.2", virtualbox_intnet: "ext"
    node.vm.provision "shell", inline: <<-SHELL
      sudo apt-get install -y git module-assistant iptables iptables-dev pkg-config linux-headers-$(uname -r) build-essential
      git clone git://github.com/aabc/ipt-netflow.git ipt-netflow
      cd ipt-netflow
      m-a prepare
      ./configure
      make all install
      depmod
    SHELL
    node.vm.provision "shell", run: "always", inline: <<-SHELL
      sudo modprobe ipt_NETFLOW destination=10.0.0.3:2055 protocol=9
      #sudo modprobe ipt_NETFLOW destination=10.0.0.3:2055 protocol=7
      #sudo modprobe ipt_NETFLOW destination=10.0.0.3:2055
      sudo iptables -I INPUT -j NETFLOW
      sudo iptables -I OUTPUT -j NETFLOW
    SHELL
  end

  config.vm.define "collector" do |node|
    node.vm.hostname = "collector"
    node.vm.network "private_network", ip: "10.0.0.3", virtualbox_intnet: "ext"
    node.vm.provision "shell", inline: <<-SHELL
      sudo apt install python3 python3-pip
      sudo pip3 install ipdb
    SHELL
    node.vm.provision "shell", run: "always", inline: <<-SHELL
      #python3 /vagrant/netflow_exporter.py
    SHELL
  end
end
