# PCBank - OCP 3.6 Build Book

- Non-Prod Environment - Connectivity Information

  URL: [https://65.93.204.155](https://65.93.204.155) 

  New - 142.112.24.212

  ![](https://static.notion-static.com/04d67a8cf0c34f9aaf15ece5ae066840/Screenshot_2017-10-27_11.42.34.png)

  ![](https://static.notion-static.com/0b5828c333e4443e9e86746cb8f209bf/Screenshot_2017-10-27_11.43.10.png)

  [FortiClientOnlineInstaller.dmg](https://static.notion-static.com/8be41bdb44174e49952d59a4b95324f2/FortiClientOnlineInstaller.dmg)

  Install Software

  ![](https://static.notion-static.com/55d1e17e33cd42aba7e3aa6a3433fe9f/Screenshot_2017-10-27_11.45.41.png)

  Run the Client and Creat New Connection

  ![](https://static.notion-static.com/2188d26a106644dc9f9356659187f82e/Screenshot_2017-10-27_11.49.03.png)

  Connect to VPN

  ![](https://static.notion-static.com/58d2af39912d4f58a430156d43051da4/Screenshot_2017-10-27_11.49.55.png)

  Verify Connectivity

  ![](https://static.notion-static.com/65dd6a88a7264763a09a5e685d824e72/Screenshot_2017-10-27_11.50.11.png)

- RHN Account Info

      subscription-manager register --username stephen.jay@scalar.ca --password xxx
      
      subscription-manager register --username mbarsoum --password xxx

- Fixing RHN Registration - Registration was not configured properly
  - Also not that this environment is using RHNetwork since Satellite 6 was not configured and available to be used. Shoudl move to Satellite at some point.

      [root@cb1ivansn01 ~]# subscription-manager unregister
      Unregistering from: subscription.rhsm.redhat.com:443/subscription
      System has been unregistered.
      
      [root@cb1ivansn01 ~]# subscription-manager clean
      All local data removed
      
      [root@cb1ivansn01 ~]# subscription-manager register
      Registering to: subscription.rhsm.redhat.com:443/subscription
      Username: mbarsoum
      Password: 
      
      The system has been registered with ID: 6e5f9753-608a-40de-a39f-bda663f65bd4 
      
      FOR VIRTUAL MACHINES
      [root@cb1ivansn01 ~]# subscription-manager attach --pool 8a85f98b5e2ed490015e300cde4706df
      
      Successfully attached a subscription for: Red Hat OpenShift Container Platform, Premium (1-2 Sockets)
      
      FOR APP NODES (BARE METAL)
      [root@cb1ivansn01 ~]# subscription-manager attach --pool 8a85f98b5e2ed490015e300cdfd0074c
      
      [root@cb1ivansn01 ~]# subscription-manager repos --disable="*"
      ...
      
      sudo subscription-manager repos \
       --enable="rhel-7-server-rpms" \
       --enable="rhel-7-server-extras-rpms" \
       --enable="rhel-7-server-ose-3.6-rpms" \
       --enable="rhel-7-fast-datapath-rpms"
      
      Repository 'rhel-7-server-rpms' is enabled for this system.
      Repository 'rhel-7-server-ose-3.6-rpms' is enabled for this system.
      Repository 'rhel-7-server-extras-rpms' is enabled for this system.
      Repository 'rhel-7-fast-datapath-rpms' is enabled for this system.
      
      [root@cb1ivansn01 ~]# yum clean all && yum repolist

- Utilizing Screen when doing install to protect from disconnects

  Screen Stuff

      sudo yum install screen
      
      screen 
      
      to break out of it do 
      control + a then d
      
      you will see something like this
      [detached from 11550.pts-0.cb1ividmn01]
      
      to view what sessions you have do 
      screen -ls
      
      example
      [root@cb1ividmn01 ~]# screen -ls
      There is a screen on:
       11550.pts-0.cb1ividmn01 (Detached)
      1 Socket in /var/run/screen/S-root.
      
      to re-attach do screen -r and the name of that session 
      
      screen -r 11550.pts-0.cb1ividmn01
      
      to exit from the screen go into it and type exit
      
      you will see
      [screen is terminating]
      [root@cb1ividmn01 ~]#
      
      detach - control + a then d
      
      you will see something like this
      [detached from 11550.pts-0.cb1ividmn01]
      
      reattach screen -r <name of session>
      
      use screen -ls to get sessions

- Projects Links - JIRA connectivity information (Capco)

   [JIRA](https://capco-cardinal.atlassian.net/secure/BrowseProjects.jspa?selectedCategory=all) 

- Active Directory - Login Information / Intergration

      ID: test1
      PW: Pcbank!est
      Group: sgOCPAdmin
      
      ID: test2
      PW: Pcbank!est
      Group: sgOCPUsers
      
      These are the two ad users that are in these two individual groups. if you OC login with these users that each have individual roles admin and user

      # BEGIN ANSIBLE MANAGED ACTIVE DIRECTORY BLOCK #
       - name: "Active Directory - PCBank"
       challenge: true
       login: true
       mappingMethod: add
       provider:
       apiVersion: v1
       kind: LDAPPasswordIdentityProvider
       attributes:
       id:
       - cn
       - sAMAccountName
       bindDN: "CN=svcOCPConnect,OU=pcfServiceAccounts,DC=pcf,DC=local"
       bindPassword: "Pc!dm1nOCP@$99"
       insecure: true
       url: "ldap://CB1IVDCN01.pcf.local:389/dc=pcf,dc=local?sAMAccountName?sub?(memberOf=CN=sgOCPAll,OU=pcfSecurityGroups,DC=pcf,DC=local)"
      # END ANSIBLE MANAGED ACTIVE DIRECTORY BLOCK #

- Jumpbox Connection Details - Ansible Host

  ssh root@cb1ivansn01.le.dp.pcf.local -p Pcbank!dmin

- Non-Prod - Virtual machine Information

  Login info: root / Pcbank!dmin

   **Host Information:** 

  FQDN is [SERVERNAME.](http://servername.PCB.COM) PCF.Local

  PCF.Local

  - DNS Naming Convention

    i. Parent-Zone = PCF.LOCAL

    ii. Child Domain = DP (Short for “Digital Platform”)

    iii. Second Child Domain = LE (Short for “Lower Environment”)

    1. If this were the production environment then this child domain would be “HE” for “Higher Environment”

    iv. Full structure of DNS space = LE.DP.PCF.LOCAL

    v. Example of a Server in this space =  **ServerX.LE.DP.PCF.LOCAL** 

  - Host list = All

         [cb1avocpmn01.le.dp.pcf.local](http://cb1avocpm01.le.dp.pcf.local) 
        cb1avocpmn02.le.dp.pcf.local
        cb1avocpmn02.le.dp.pcf.local
         [cb1avocpin01.le.dp.pcf.local](http://cb1avocpi01.le.dp.pcf.local) 
        cb1avocpin02.le.dp.pcf.local
        cb1avocpin03.le.dp.pcf.local
        cb1avocpin04.le.dp.pcf.local
        cb1avocpin05.le.dp.pcf.local
         [cb1avocpin06.le.dp.pcf.local](http://cb1avocpi06.le.dp.pcf.local) 
         [cb1avocpan01.le.dp.pcf.local](http://cb1avocpa01.le.dp.pcf.local) 
        cb1avocpan02.le.dp.pcf.local
        cb1avocpan03.le.dp.pcf.local
        cb1avocpan04.le.dp.pcf.local
        cb1ivansnn01.le.dp.pcf.local

  - Resolv.conf

    cat /etc/resolv.conf

    nameserver 10.69.120.2
    nameserver 10.69.120.3
    search le.dp.pcf.local

  - incfg-enp13s0 - Example

    TYPE="Ethernet"
    BOOTPROTO="none"
    DEVICE="enp13s0"
    ONBOOT="yes"
    DNS1="10.69.120.2"
    DNS2="10.69.120.3"
    DNS3="10.69.120.4"
    DOMAIN="le.dp.pcf.local"

  - Host File - /etc/hosts

        127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4
        ::1 localhost localhost.localdomain localhost6 localhost6.localdomain6
        
        #ANSIBLE
        10.69.65.2 ansn01
        
        #MASTERS
        10.69.64.50	ocpm01
        10.69.64.51	ocpm02
        10.69.64.52	ocpm03
        
        #Infrastructure Nodes
        10.69.64.53	ocpi01
        10.69.64.54	ocpi02
        10.69.64.55	ocpi03
        10.69.64.56	ocpi04
        10.69.64.57	ocpi05
        10.69.64.58	ocpi06
        
        #Application Nodes
        10.69.64.59	ocpa01
        10.69.64.60	ocpa02
        10.69.64.61	ocpa03
        10.69.64.62	ocpa04
        
        #IDM
        10.69.120.5	idmn01
        10.69.120.6	idmn02

        #ANSIBLE
        
        10.69.65.2	cb1ivansn01.le.dp.pcf.local
        10.69.65.2 ansn01
        
        #MASTERS
        
        10.69.64.50	 [cb1avocpmn01.le.dp.pcf.local](http://cb1avocpm01.le.dp.pcf.local) 
        10.69.64.51	cb1avocpmn02.le.dp.pcf.local
        10.69.64.52	cb1avocpmn03.le.dp.pcf.local
        10.69.64.50	ocpm01
        10.69.64.51	ocpm02
        10.69.64.52	ocpm03
        10.69.64.50	master.le.dp.pcf.local
        10.69.64.51	master.le.dp.pcf.local
        10.69.64.52	master.le.dp.pcf.local
        
        #Infrastructure Nodes
        
        10.69.64.53	cb1avocpin01.le.dp.pcf.local
        10.69.64.54	cb1avocpin02.le.dp.pcf.local
        10.69.64.55	cb1avocpin03.le.dp.pcf.local
        10.69.64.56	cb1avocpin04.le.dp.pcf.local
        10.69.64.57	cb1avocpin05.le.dp.pcf.local
        10.69.64.58	cb1avocpin06.le.dp.pcf.local
        10.69.64.53	ocpi01
        10.69.64.54	ocpi02
        10.69.64.55	ocpi03
        10.69.64.56	ocpi04
        10.69.64.57	ocpi05
        10.69.64.58	ocpi06
        
        #Application Nodes
        
        10.69.64.59	cb1avocpan01.le.dp.pcf.local
        10.69.64.60	cb1avocpan02.le.dp.pcf.local
        10.69.64.61	cb1avocpan03.le.dp.pcf.local
        10.69.64.62	cb1avocpan04.le.dp.pcf.local
        10.69.64.59	ocpa01
        10.69.64.60	ocpa02
        10.69.64.61	ocpa03
        10.69.64.62	ocpa04
        
        #IDM
        
        10.69.120.5	cb1ividmn01.le.dp.pcf.local
        10.69.120.6	 [cb1ividmn02.le.dp.pcf.local](http://cb1ividmn02.le.dp.pcf.local) 
        10.69.120.5	idmn01
        10.69.120.6	idmn02

  - Full DNS Breakdown

        #ANSIBLE
        
        10.69.65.2	cb1ivansn01.le.dp.pcf.local
        10.69.65.2 ansn01
        
        #MASTERS
        
        10.69.64.50	cb1avocpmn01.le.dp.pcf.local
        10.69.64.51	cb1avocpmn02.le.dp.pcf.local
        10.69.64.52	cb1avocpmn03.le.dp.pcf.local
        10.69.64.50	ocpm01
        10.69.64.51	ocpm02
        10.69.64.52	ocpm03
        10.69.64.50	master.le.dp.pcf.local
        10.69.64.51	master.le.dp.pcf.local
        10.69.64.52	master.le.dp.pcf.local
        
        #OCP Console and API Server here
        10.69.64.50	ocp.le.dp.pcf.local
        10.69.64.51	ocp.le.dp.pcf.local
        10.69.64.52	ocp.le.dp.pcf.local
        
        #Infrastructure Nodes
        
        10.69.64.53	cb1avocpin01.le.dp.pcf.local
        10.69.64.54	cb1avocpin02.le.dp.pcf.local
        10.69.64.55	cb1avocpin03.le.dp.pcf.local
        10.69.64.56	cb1avocpin04.le.dp.pcf.local
        10.69.64.57	cb1avocpin05.le.dp.pcf.local
        10.69.64.58	cb1avocpin06.le.dp.pcf.local
        10.69.64.53	ocpi01
        10.69.64.54	ocpi02
        10.69.64.55	ocpi03
        10.69.64.56	ocpi04
        10.69.64.57	ocpi05
        10.69.64.58	ocpi06
        
        #Applications will live here
        10.69.64.53	*.apps.ocp.le.dp.pcf.local
        10.69.64.54	*.apps.ocp.le.dp.pcf.local
        10.69.64.55	*.apps.ocp.le.dp.pcf.local
        10.69.64.56	*.apps.ocp.le.dp.pcf.local
        
        #Application Nodes
        
        10.69.64.59	cb1avocpan01.le.dp.pcf.local
        10.69.64.60	cb1avocpan02.le.dp.pcf.local
        10.69.64.61	cb1avocpan03.le.dp.pcf.local
        10.69.64.62	cb1avocpan04.le.dp.pcf.local
        10.69.64.59	ocpa01
        10.69.64.60	ocpa02
        10.69.64.61	ocpa03
        10.69.64.62	ocpa04
        
        #IDM
        
        10.69.120.5	cb1ividmn01.le.dp.pcf.local
        10.69.120.6	cb1ividmn02.le.dp.pcf.local
        10.69.120.5	idmn01
        10.69.120.6	idmn02
        
        #We will use this for the subdomain for IDM
        
        nix.le.dp.pcf.local

  - Satellite Info

     [https://cb1ivsatn01.le.dp.pcf.local](https://cb1ivsatn01.le.dp.pcf.local) 

  - OCP Pool ID's

    Red Hat OpenShift Enterprise Application Node

    8a85f98b5e2ed490015e300cddf706ba = 5

    8a85f98b5e2ed490015e300cdfd0074c = 5

    8a85f98b5e2ed490015e300cdfff0771 = Unlimited

    8a85f98b5e2ed490015e300cde4706df = Unlimited

    Red Hat OpenShift Container Platform Broker/Master Infrastructure

    8a85f9815e346bc0015e348ca4a83658 = 155

    8a85f9815e346bc0015e348ca3f63635 = 152

  - iSCSI initiators

        iqn.2017-12.com.redhat:cb1avocpin01
        iqn.2017-12.com.redhat:cb1avocpin02
        iqn.2017-12.com.redhat:cb1avocpin03
        iqn.2017-12.com.redhat:cb1avocpin04
        iqn.2017-12.com.redhat:cb1avocpin05
        iqn.2017-12.com.redhat:cb1avocpin06

  - Target IP and Lun info

        192.168.211.10
        192.168.211.11

        size=200G features='4 queue_if_no_path pg_init_retries 50 retain_attached_hw_handle' hwhandler='1 alua' wp=rw
        
        |-+- policy='service-time 0' prio=50 status=active
        
        
        size=200G features='4 queue_if_no_path pg_init_retries 50 retain_attached_hw_handle' hwhandler='1 alua' wp=rw
        
        |-+- policy='service-time 0' prio=50 status=active
        
        
        size=200G features='4 queue_if_no_path pg_init_retries 50 retain_attached_hw_handle' hwhandler='1 alua' wp=rw
        
        |-+- policy='service-time 0' prio=50 status=active

  ---

  Here is the resource configuration as instructed by CapCo for the OCP server builds:

  ![](https://static.notion-static.com/f6ea8566a1f94f2eaba594fd00fed996/Screenshot_2017-10-27_12.01.15.png)

  ---

  - DNS Request Details + IDM

    Indi, per our chat. Here is what we need for IDM

    Also looping in Aly

     **NEED VPN ACCESS FOR ALY** 

     [aly.khimji@arctiq.ca](mailto:aly.khimji@arctiq.ca) 

    416-602-3513

     **IDM VIRTUAL MACHINES** 

    x2 - RHEL 7.4

    8G - 2 or 4 x vcpu

    50GB disk is fine

     **NED THE FOLLOWING DNS UPDATES ASAP** 

    10.69.64.51 - CB1AVOCPM02 - OCP Host Communication

    10.69.64.52 - CB1AVOCPM03 - OCP Host Communication

    10.69.64.53 - CB1AVOCPI04 - OCP Host Communication

    10.69.64.54 - CB1AVOCPI05 - OCP Host Communication

    10.69.64.55 - CB1AVOCPI06 - OCP Host Communication

    10.69.64.56 - CB1AVOCPI07 - OCP Host Communication

    10.69.64.57 - CB1AVOCPI08 - OCP Host Communication

    10.69.64.58 - CB1AVOCPI09 - OCP Host Communication

    10.69.64.59 - CB1AVOCPA10 - OCP Host Communication (B200 Blade 5)

    10.69.64.60 - CB1AVOCPA11 - OCP Host Communication (B200 Blade 5)

    10.69.64.61 - CB1AVOCPA12 - OCP Host Communication (B200 Blade 5)

    10.69.64.62 - CB1AVOCPA13 - OCP Host Communication (B200 Blade 5)

     **ADDITIONAL DNS ENTIRES** 

    masters.pcb.com

    Just create an entry for all - round robin is fine for now

    10.69.64.50 masters.pcb.com

    10.69.64.51 masters.pcb.com

    10.69.64.52 masters.pcb.com

     **EXTERNAL DNS NAMES - THESE WILL POINT TO LOAD BALANCERS AT SOME POINT** 

    10.69.64.53 apps.ocp.pcb

    10.69.64.54 apps.ocp.pcb

    10.69.64.55 apps.ocp.pcb

    10.69.64.56 apps.ocp.pcb

    10.69.64.50 ocp.pcb

    10.69.64.51 ocp.pcb

    10.69.64.52 ocp.pcb

- Non-Prod - OCP Build information
  - Current Host File - Validate this again server ***

        [OSEv3:children]
        masters
        nodes
        etcd
        
        # Set variables common for all OSEv3 hosts
        [OSEv3:vars]
        
        # SSH user, this user should allow ssh based auth without requiring a password
        # If ansible_ssh_user is not root, ansible_sudo must be set to true
        
        # Generic settings
        ansible_ssh_user=root
        #ansible_become=true
        #ansible_become=yes
        #ansible_sudo=true
        
        deployment_type=openshift-enterprise
        openshift_master_cluster_method=native
        openshift_clock_enabled=true
        openshift_node_kubelet_args={'pods-per-core': ['10'], 'max-pods': ['250'], 'image-gc-high-threshold': ['90'], 'image-gc-low-threshold': ['80']}
        osm_default_node_selector="region=app"
        
        # Customer specific naming conventions
        openshift_master_cluster_hostname=master.le.dp.pcf.local
        openshift_master_cluster_public_hostname=ocp.le.dp.pcf.local
        openshift_master_default_subdomain=apps.ocp.le.dp.pcf.local
        
        # Start with HTPASSWD (switch to LDAP post-install)
        openshift_master_identity_providers=[{'name': 'htpasswd_auth','login': 'true', 'challenge': 'true','kind': 'HTPasswdPasswordIdentityProvider','filename': '/etc/origin/master/htpasswd'}]
        
        # Allow all auth - This will allow anyone to login/create an account after OSE is installed)
        #openshift_master_identity_providers=[{'name': 'allow_all', 'login': 'true', 'challenge': 'true', 'kind': 'AllowAllPasswordIdentityProvider'}]
        
        openshift_disable_check=docker_image_availability,disk_availability,docker_storage
        
        # Customer specific network settings
        os_sdn_network_plugin_name=redhat/openshift-ovs-multitenant
        osm_cluster_network_cidr=10.1.0.0/16
        osm_host_subnet_length=10
        openshift_master_portal_net=172.30.0.0/16
        openshift_docker_insecure_registries=172.30.0.0/16
        
        #openshift_http_proxy=http://xxx.ca:80/
        #openshift_https_proxy=http://xxx.ca:80/
        #openshift_no_proxy=xxx.ca,xxx.ca
        
        # Logging settings
        #openshift_logging_use_ops=false
        #openshift_logging_master_url=master.le.dp.pcf.local
        #openshift_logging_public_master_url=ocp.le.dp.pcf.local
        #openshift_logging_namespace=logging
        #openshift_logging_install_logging=true
        #openshift_logging_kibana_nodeselector={"function":"logging"}
        #openshift_logging_es_nodeselector={"function":"logging"}
        #openshift_logging_curator_ops_nodeselector={"function":"logging"}
        
        # Host group for masters
        [masters]
        cb1avocpmn01.le.dp.pcf.local openshift_ip=10.69.64.50
        cb1avocpmn02.le.dp.pcf.local openshift_ip=10.69.64.51
        cb1avocpmn03.le.dp.pcf.local openshift_ip=10.69.64.52
        
        #Multi Master Setup
        
        [etcd]
        cb1avocpmn01.le.dp.pcf.local openshift_ip=10.69.64.50
        cb1avocpmn02.le.dp.pcf.local openshift_ip=10.69.64.51
        cb1avocpmn03.le.dp.pcf.local openshift_ip=10.69.64.52
        
        # host group for nodes, includes region info
        [nodes]
        cb1avocpmn01.le.dp.pcf.local openshift_node_labels="{'region': 'master', 'zone': 'nonprod'}" openshift_scheduleable=false openshift_hostname=cb1avocpmn01.le.dp.pcf.local openshift_ip=10.69.64.50
        cb1avocpmn02.le.dp.pcf.local openshift_node_labels="{'region': 'master', 'zone': 'nonprod'}" openshift_scheduleable=false openshift_hostname=cb1avocpmn02.le.dp.pcf.local openshift_ip=10.69.64.51
        cb1avocpmn03.le.dp.pcf.local openshift_node_labels="{'region': 'master', 'zone': 'nonprod'}" openshift_scheduleable=false openshift_hostname=cb1avocpmn03.le.dp.pcf.local openshift_ip=10.69.64.52
        cb1avocpin01.le.dp.pcf.local openshift_node_labels="{'region': 'infra', 'zone': 'nonprod', 'function': 'registry-router'}" openshift_schedulable=true openshift_hostname=cb1avocpin01.le.dp.pcf.local openshift_ip=10.69.64.53
        cb1avocpin02.le.dp.pcf.local openshift_node_labels="{'region': 'infra', 'zone': 'nonprod', 'function': 'registry-router'}" openshift_schedulable=true openshift_hostname=cb1avocpin02.le.dp.pcf.local openshift_ip=10.69.64.54
        cb1avocpin03.le.dp.pcf.local openshift_node_labels="{'region': 'infra', 'zone': 'nonprod', 'function': 'registry-router'}" openshift_schedulable=true openshift_hostname=cb1avocpin03.le.dp.pcf.local openshift_ip=10.69.64.55
        cb1avocpin04.le.dp.pcf.local openshift_node_labels="{'region': 'infra', 'zone': 'nonprod', 'function': 'registry-router'}" openshift_schedulable=true openshift_hostname=cb1avocpin04.le.dp.pcf.local openshift_ip=10.69.64.56
        cb1avocpin05.le.dp.pcf.local openshift_node_labels="{'region': 'infra', 'zone': 'nonprod', 'function': 'metrics'}" openshift_schedulable=true openshift_hostname=cb1avocpin05.le.dp.pcf.local openshift_ip=10.69.64.57
        cb1avocpin06.le.dp.pcf.local openshift_node_labels="{'region': 'infra', 'zone': 'nonprod', 'function': 'logging'}" openshift_schedulable=true openshift_hostname=cb1avocpin06.le.dp.pcf.local openshift_ip=10.69.64.58
        cb1apocpan01.le.dp.pcf.local openshift_node_labels="{'region': 'app', 'zone': 'nonprod'}" openshift_schedulable=true openshift_hostname=cb1apocpan01.le.dp.pcf.local openshift_ip=10.69.64.59
        cb1apocpan02.le.dp.pcf.local openshift_node_labels="{'region': 'app', 'zone': 'nonprod'}" openshift_schedulable=true openshift_hostname=cb1apocpan02.le.dp.pcf.local openshift_ip=10.69.64.60
        cb1apocpan03.le.dp.pcf.local openshift_node_labels="{'region': 'app', 'zone': 'nonprod'}" openshift_schedulable=true openshift_hostname=cb1apocpan03.le.dp.pcf.local openshift_ip=10.69.64.61
        cb1apocpan04.le.dp.pcf.local openshift_node_labels="{'region': 'app', 'zone': 'nonprod'}" openshift_schedulable=true openshift_hostname=cb1apocpan04.le.dp.pcf.local openshift_ip=10.69.64.62

  - Setup the Ansible host machine

        sudo yum install git -y
        sudo git clone [https://kylearctiq@github.com/ArctiqTeam/ocp_pcbank](https://kylearctiq@github.com/ArctiqTeam/ocp_pcbank) 
        
        cd ocp_pcbank
        sudo chmod +x *.sh

        >> add ocpadmin to all servers in node_list file (do this root)
        for node in $(cat node_list_ips); do ssh $node 'useradd ocpadmin'; done
        
        >> enable passwordless sudo (do this as root) 
        for node in $(cat node_list_ips); do ssh $node 'echo "ocpadmin ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/99-ocpadmin'; done
        
        >> enable passwordless sudo (do this as root) 
        for node in $(cat node_list_ips); do ssh $node 'echo "ocpadmin ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers'; done
        
        >> set the passwd for this user, you will need it when you copy over the ssh-key (as root)
        for node in $(cat node_list_ips); do ssh $node 'echo Arctiqws2018 | passwd ocpadmin --stdin ' ; done

        su - ocpadmin
        
        ssh-keygen -f /home/ocpadmin/.ssh/id_rsa -N ''
        
        Generating public/private rsa key pair.
        Your identification has been saved in /home/ocpadmin/.ssh/id_rsa.
        Your public key has been saved in /home/ocpadmin/.ssh/id_rsa.pub.
        The key fingerprint is:
        SHA256:8+by5Zjqwi4zswfED/0IT7kf58lRDMxUPKKVEi3dQDk ocpadmin@cb1ivansn01.le.dp.pcf.local
        The key's randomart image is:
        +---[RSA 2048]----+
        | .O+B. |
        | o E + |
        | . . . = = . |
        | = + . o |
        | . * +S . |
        | . = ooo |
        | o . =oo. |
        | = + oo+= |
        | .O.oo+= . |
        +----[SHA256]-----+

        ssh localhost
        
        ssh-keygen -f /root/.ssh/id_rsa -N ''
        
        for node in $(cat node_list_ips); do ssh-copy-id $node; done

        for node in $(cat node_list_ips); do scp /etc/hosts root@$node:/etc/hosts; done

        
        sudo subscription-manager list --available --matches "*OpenShift*"
        
        sudo subscription-manager register
        
        FOR VIRTUAL MACHINES
        [root@cb1ivansn01 ~]# subscription-manager attach --pool 8a85f98b5e2ed490015e300cde4706df
        
        Successfully attached a subscription for: Red Hat OpenShift Container Platform, Premium (1-2 Sockets)
        
        FOR APP NODES (BARE METAL)
        [root@cb1ivansn01 ~]# subscription-manager attach --pool 8a85f98b5e2ed490015e300cdfd0074c
        
        Openshift
        sudo subscription-manager repos --disable="*"
        
        yum repolist
        
        yum-config-manager --disable \*
        
        sudo subscription-manager repos \
         --enable="rhel-7-server-rpms" \
         --enable="rhel-7-server-extras-rpms" \
         --enable="rhel-7-server-ose-3.6-rpms" \
         --enable="rhel-7-fast-datapath-rpms"
        
        yum clean all && yum repolist
        
        sudo yum install -y atomic-openshift-utils

        ansible-playbook -i hosts.openshiftprepall ansible_login_prep.yml
        
        PLAY RECAP *****************************************************************************************************************************************
        cb1avocpa01.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpa02.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpa03.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpa04.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpi01.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpi02.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpi03.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpi04.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpi05.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpi06.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpm01.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1avocpm02.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0
        cb1ivansn01.le.dp.pcf.local : ok=2 changed=1 unreachable=0 failed=0

        PLAYBOOK
        
        ---
        - hosts: nodes
        # sudo: True
         remote_user: xxx
         become: True
         become_method: sudo
        
         vars_prompt:
         - name: "rhel_pool_id"
         prompt: "Enter RHN Application POOL ID ?"
        
         tasks:
        
         - name: attach node to subscription pool
         command: subscription-manager attach --pool {{ item }}
         register: task_result
         until: task_result.rc == 0
         retries: 10
         delay: 1
         ignore_errors: no
         with_items: '{{rhel_pool_id}}'
        
         - name: Enable only required repositories with Subscription Manager
         command: subscription-manager repos --disable="*" --enable="rhel-7-server-rpms" --enable="rhel-7-server-extras-rpms" --enable="rhel-7-server-ose-3.7-rpms" --enable="rhel-7-fast-datapath-rpms"
        
         - name: Run yum update
         yum: name=* state=latest
        
         - yum: name=wget state=latest
         - yum: name=dnsmasq state=latest
         - yum: name=nano state=latest
         - yum: name=vim-enhanced state=latest
         - yum: name=net-tools state=latest
         - yum: name=bind-utils state=latest
         - yum: name=git state=latest
         - yum: name=iptables-services state=latest
         - yum: name=bridge-utils state=latest
         - yum: name=bash-completion state=latest
         - yum: name=kexec-tools state=latest
         - yum: name=sos state=latest
         - yum: name=psacct state=latest
         - yum: name=atomic-openshift-utils state=latest
         - yum: name=atomic-openshift-excluder state=latest
         - yum: name=atomic-openshift-docker-excluder state=latest
        
         - name: Unexclude atomic-openshift package for the duration of the install
         command: atomic-openshift-excluder unexclude

  - Configure Nodes - OCP Install

        ansible-playbook -i hosts.ocp.infra 2.1-ansible.ocpinfra.prep.yml
        
        PLAY RECAP *****************************************************************************************************************************************
        cb1avocpi01.le.dp.pcf.local : ok=19 changed=16 unreachable=0 failed=0
        cb1avocpi02.le.dp.pcf.local : ok=19 changed=16 unreachable=0 failed=0
        cb1avocpi03.le.dp.pcf.local : ok=19 changed=16 unreachable=0 failed=0
        cb1avocpi04.le.dp.pcf.local : ok=19 changed=16 unreachable=0 failed=0
        cb1avocpi05.le.dp.pcf.local : ok=19 changed=16 unreachable=0 failed=0
        cb1avocpi06.le.dp.pcf.local : ok=19 changed=16 unreachable=0 failed=0
        cb1avocpm01.le.dp.pcf.local : ok=19 changed=16 unreachable=0 failed=0
        cb1avocpm02.le.dp.pcf.local : ok=19 changed=16 unreachable=0 failed=0

        ansible-playbook -i hosts.ocp.apps 2.2-ansible.ocp.apps.prep.yml
        
        PLAY RECAP **************************************************************************************
        cb1avocpan01.le.dp.pcf.local : ok=20 changed=16 unreachable=0 failed=0
        cb1avocpan02.le.dp.pcf.local : ok=20 changed=17 unreachable=0 failed=0
        cb1avocpan03.le.dp.pcf.local : ok=20 changed=17 unreachable=0 failed=0
        cb1avocpan04.le.dp.pcf.local : ok=20 changed=17 unreachable=0 failed=0
        
        
        PLAYBOOK
        
        ---
        - hosts: nodes
        # sudo: True
         remote_user: xxx
         become: True
         become_method: sudo
        
         vars_prompt:
         - name: "rhel_pool_id"
         prompt: "Enter RHN Application POOL ID ?"
        
         tasks:
        
         - name: attach node to subscription pool
         command: subscription-manager attach --pool {{ item }}
         register: task_result
         until: task_result.rc == 0
         retries: 10
         delay: 1
         ignore_errors: no
         with_items: '{{rhel_pool_id}}'
        
         - name: Enable only required repositories with Subscription Manager
         command: subscription-manager repos --disable="*" --enable="rhel-7-server-rpms" --enable="rhel-7-server-extras-rpms" --enable="rhel-7-server-ose-3.7-rpms" --enable="rhel-7-fast-datapath-rpms"
        
         - name: Run yum update
         yum: name=* state=latest
        
         - yum: name=wget state=latest
         - yum: name=dnsmasq state=latest
         - yum: name=nano state=latest
         - yum: name=vim-enhanced state=latest
         - yum: name=net-tools state=latest
         - yum: name=bind-utils state=latest
         - yum: name=git state=latest
         - yum: name=iptables-services state=latest
         - yum: name=bridge-utils state=latest
         - yum: name=bash-completion state=latest
         - yum: name=kexec-tools state=latest
         - yum: name=sos state=latest
         - yum: name=psacct state=latest
         - yum: name=atomic-openshift-utils state=latest
         - yum: name=atomic-openshift-excluder state=latest
         - yum: name=atomic-openshift-docker-excluder state=latest
        
         - name: Unexclude atomic-openshift package for the duration of the install
         command: atomic-openshift-excluder unexclude

        ansible-playbook -i hosts.ocp.infra 3.0-ocp-infra-docker-host-prep.yml
        
        PLAY RECAP **************************************************************************************
        cb1avocpin01.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        cb1avocpin02.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        cb1avocpin03.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        cb1avocpin04.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        cb1avocpin05.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        cb1avocpin06.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        cb1avocpmn01.le.dp.pcf.local : ok=5 changed=1 unreachable=0 failed=0
        cb1avocpmn02.le.dp.pcf.local : ok=5 changed=1 unreachable=0 failed=0
        
        PLAYBOOK
        
        ---
        - hosts: nodes
        # sudo: True
         remote_user: xxx
         become: True
         become_method: sudo
         vars:
         docker_storage_mount: /dev/sdc
        
         tasks:
        
         - name: Install Docker
         yum: name=docker state=installed update_cache=yes
         register: dockerInstalled
         notify:
         - Start Docker
        
         - meta: flush_handlers
        
         - name: Insecure Registry Config
         lineinfile: dest=/etc/sysconfig/docker regexp="^OPTIONS" line=OPTIONS='--selinux-enabled --insecure-registry xxx/16 --log-opt max-size=1M --log-opt max-file=3' backup=yes backrefs=yes state=present
         register: dockerConfigUpdated
        
         - name: Create Docker Storage Config
         blockinfile:
         dest: /etc/sysconfig/docker-storage-setup
         create: yes
         content: |
         DEVS={{ docker_storage_mount}}
         VG=docker-vg
         register: dockerStorageConfigFileCreated
         notify:
         - Stop Docker
         - Clean Docker Data
        
         - meta: flush_handlers
        
         - name: Check if LVS exists
         shell: lvs | grep docker-pool | awk '{ print $1}'
         register: dockerpoolLVS
        
         - name: Docker Storage Setup
         when: dockerpoolLVS.stdout != "docker-pool" and dockerStorageConfigFileCreated|success
         command: docker-storage-setup
         register: dockerStorageSetupComplete
         notify:
         - Stop Docker
         - Clean Docker Data
         - Start Docker
        
         - meta: flush_handlers
        
         handlers:
         - name: Start Docker
         service: name=docker state=started enabled=yes
        
         - name: Stop Docker
         service: name=docker state=stopped
        
         - name: Clean Docker Data
         command: rm -rf /var/lib/docker/*

        IF YOU NEED THIS
        
        sudo wipefs -a /dev/sdb
        
        ansible-playbook -i hosts.ocp.infra 3.1-docker-fix.yml

        ansible-playbook -i hosts.ocp.apps 3.0-ocp-app-docker-host-prep.yml
        
        ansible-playbook -i hosts.ocp.apps 3.1-docker-fix.yml
        
        PLAY RECAP **************************************************************************************
        cb1avocpan01.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        cb1avocpan02.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        cb1avocpan03.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        cb1avocpan04.le.dp.pcf.local : ok=9 changed=5 unreachable=0 failed=0
        
        docker-storage-setup
        
        INFO: Device /dev/sdb is already partitioned and is part of volume group docker-vg
        INFO: Found an already configured thin pool /dev/mapper/docker--vg-docker--pool in /etc/sysconfig/docker-storage
        INFO: Device node /dev/mapper/docker--vg-docker--pool exists.
         Logical volume docker-vg/docker-pool changed.

        sudo wipefs -a /dev/sdb
        
        ansible-playbook -i hosts.ocp.infra 3.1-docker-fix.yml

        docker-storage-setup
        
        INFO: Device /dev/sdb is already partitioned and is part of volume group docker-vg
        INFO: Found an already configured thin pool /dev/mapper/docker--vg-docker--pool in /etc/sysconfig/docker-storage
        INFO: Device node /dev/mapper/docker--vg-docker--pool exists.
         Logical volume docker-vg/docker-pool changed.

        for node in $(cat ocp_node_list); do echo $node; ssh $node '/bin/bash -c "sudo /sbin/setsebool -P virt_use_nfs 1 && sudo /sbin/setsebool -P virt_sandbox_use_nfs 1 "'; done

        ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/byo/openshift_facts.yml

        PLAY RECAP ***************************************************************************************************************************************************************************************************************************************************
        cb1apocpan01.le.dp.pcf.local : ok=69 changed=4 unreachable=0 failed=0
        cb1apocpan02.le.dp.pcf.local : ok=69 changed=4 unreachable=0 failed=0
        cb1apocpan03.le.dp.pcf.local : ok=69 changed=4 unreachable=0 failed=0
        cb1apocpan04.le.dp.pcf.local : ok=69 changed=4 unreachable=0 failed=0
        cb1avocpin01.le.dp.pcf.local : ok=69 changed=2 unreachable=0 failed=0
        cb1avocpin02.le.dp.pcf.local : ok=69 changed=2 unreachable=0 failed=0
        cb1avocpin03.le.dp.pcf.local : ok=69 changed=2 unreachable=0 failed=0
        cb1avocpin04.le.dp.pcf.local : ok=69 changed=2 unreachable=0 failed=0
        cb1avocpin05.le.dp.pcf.local : ok=69 changed=2 unreachable=0 failed=0
        cb1avocpin06.le.dp.pcf.local : ok=69 changed=2 unreachable=0 failed=0
        cb1avocpmn01.le.dp.pcf.local : ok=71 changed=2 unreachable=0 failed=0
        cb1avocpmn02.le.dp.pcf.local : ok=70 changed=2 unreachable=0 failed=0
        cb1avocpmn03.le.dp.pcf.local : ok=70 changed=2 unreachable=0 failed=0
        localhost : ok=11 changed=0 unreachable=0 failed=0

        MAIN INSTALLER
        
        ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/byo/config.yml -vvv

        FROM THE OPENSHIFT-INFRA PROJECT
        
        ansible-playbook -i hosts /usr/share/ansible/openshift-ansible/playbooks/byo/openshift-cluster/openshift-metrics.yml \
         -e openshift_metrics_install_metrics=True \
         -e openshift_metrics_hawkular_hostname=hawkular-metrics.apps.ocp.le.dp.pcf.local \
         -e openshift_metrics_cassandra_pvc_size=50G \
         -e openshift_metrics_cassandra_storage_type=emptydir
        
        PLAY RECAP *************************************************************************************************************************************************
        cb1avocpmn01.le.dp.pcf.local : ok=172 changed=46 unreachable=0 failed=0
        cb1avocpmn02.le.dp.pcf.local : ok=16 changed=4 unreachable=0 failed=0
        cb1avocpmn03.le.dp.pcf.local : ok=16 changed=4 unreachable=0 failed=0
        localhost : ok=11 changed=0 unreachable=0 failed=0
        
        oc patch rc hawkular-cassandra-1 -p "spec:
         template:
         spec:
         nodeSelector:
         region: infra
         function: metrics"
        
        oc patch rc hawkular-metrics -p "spec:
         template:
         spec:
         nodeSelector:
         region: infra
         function: metrics"
        
        oc patch rc heapster -p "spec:
         template:
         spec:
         nodeSelector:
         region: infra
         function: metrics"
        
        oc delete pods --all -n openshift-infra

        ansible -i node_list masters -m lineinfile -a "dest=/etc/origin/master/master-config.yaml line=' loggingPublicURL: https://kibana.apps.ocp.le.dp.pcf.local' state=present insertafter='assetConfig:' backup=yes"
        ansible -i node_list masters -m service -a "name=atomic-openshift-master-controllers enabled=yes state=restarted"
        ansible -i node_list masters -m service -a "name=atomic-openshift-master-api enabled=yes state=restarted"
        
        oc project logging
        oc adm policy add-scc-to-user privileged \
         system:serviceaccount:logging:aggregated-logging-elasticsearch
        
        sudo ansible-playbook -i hosts \
         /usr/share/ansible/openshift-ansible/playbooks/byo/openshift-cluster/openshift-logging.yml

  - Post Stuff - Users adn PV's

        sudo touch /etc/openshift/openshift-passwd
        sudo htpasswd /etc/openshift/openshift-passwd ocpadmin
        sudo htpasswd /etc/openshift/openshift-passwd ocpdev
        sudo oadm policy add-cluster-role-to-user admin ocpadmin
        
        Pcbank!dmin

        echo ***copy password file to all nodes (replace with playbook)
        
        ansible -i ocpm01, -b -m copy -a "src=/etc/openshift/openshift-passwd dest=/etc/openshift/openshift-passwd" all
        ansible -i ocpm02, -b -m copy -a "src=/etc/openshift/openshift-passwd dest=/etc/openshift/openshift-passwd" all
        ansible -i ocpm03, -b -m copy -a "src=/etc/openshift/openshift-passwd dest=/etc/openshift/openshift-passwd" all
        
        ansible -i ocpm01, -b -m copy -a "src=/etc/openshift/openshift-passwd dest=/etc/origin/master/htpasswd" all
        ansible -i ocpm02, -b -m copy -a "src=/etc/openshift/openshift-passwd dest=/etc/origin/master/htpasswd" all
        ansible -i ocpm03, -b -m copy -a "src=/etc/openshift/openshift-passwd dest=/etc/origin/master/htpasswd" all
        
        
        /etc/origin/master/htpasswd

  - Restart Services

        atomic-openshift-master-controllers
        atomic-openshift-master-api

  - Post Activities - Troubleshooting

        oc get hostsubnet
        
        sudo systemctl restart openvswitch
        
        Job for atomic-openshift-node.service failed because the control process exited with error code. See "systemctl status atomic-openshift-node.service" and "journalctl -xe" for details.
        
        cd /etc/cni/net.d
        
        [root@cb1avocpmn01 net.d]# ls
        
        sudo nano /etc/cni/net.d/80-openshift-sdn.conf
        
        [root@cb1avocpmn01 net.d]# cat 80-openshift-sdn.conf
        
        {
         "cniVersion": "0.1.0",
         "name": "openshift-sdn",
         "type": "openshift-sdn"
        }
        [root@cb1avocpmn01 net.d]#
        
        
        sudo nano /etc/cni/net.d/80-openshift-sdn.conf
        
        
        On the node, check:
        if the openshift sdn is installed correctly - "rpm -q atomic-openshift-sdn-ovs"
        check the file if exists and has multitenant plugin - "cat /etc/cni/net.d/80-openshift-sdn.conf"
        check if the all repos are enabled
        
        
        scp root@cb1ivansn01.le.dp.pcf.local:/home/ocpadmin/pcbank_ansible.log /Users/kyle_bassett
        
        

  - Kube config

        apiVersion: v1
        clusters:
        - cluster:
         certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM2akNDQWRLZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFtTVNRd0lnWURWUVFEREJ0dmNHVnU$
         server: https://master.le.dp.pcf.local:8443
         name: master-le-dp-pcf-local:8443
        - cluster:
         certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM2akNDQWRLZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFtTVNRd0lnWURWUVFEREJ0dmNHVnU$
         server: https://ocp.le.dp.pcf.local:8443
         name: ocp-le-dp-pcf-local:8443
        contexts:
        - context:
         cluster: master-le-dp-pcf-local:8443
         namespace: default
         user: system:admin/master-le-dp-pcf-local:8443
         name: default/master-le-dp-pcf-local:8443/system:admin
        - context:
         cluster: ocp-le-dp-pcf-local:8443
         namespace: default
         user: system:admin/master-le-dp-pcf-local:8443
         name: default/ocp-le-dp-pcf-local:8443/system:admin
        current-context: default/master-le-dp-pcf-local:8443/system:admin
        kind: Config
        preferences: {}
        users:
        - name: system:admin/master-le-dp-pcf-local:8443
         user:
         client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUREVENDQWZXZ0F3SUJBZ0lCQmpBTkJna3Foa2lHOXcwQkFRc0ZBREFtTVNRd0lnWURWUVFEREJ0dmNHVnUKYz$
         client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdS9EWitsNXprR0ZwTWx2V1d4dGRsd3plb3pENCtuR0FqVC94Qy95SHlQSnZXazh2CkNpK0$

  - Logging oauth issue

        [root@cb1avocpmn01 ~]# oc delete oauthclient kibana-proxy
        oauthclient "kibana-proxy" deleted
        
         [https://kubernetes.default.svc.cluster.local:443](https://kubernetes.default.svc.cluster.local:443) 

  - NodeList File

        10.69.65.2 
        10.69.64.50
        10.69.64.51
        10.69.64.52
        10.69.64.53
        10.69.64.54
        10.69.64.55
        10.69.64.56
        10.69.64.57
        10.69.64.58
        10.69.64.59
        10.69.64.60
        10.69.64.61
        10.69.64.62
        10.69.64.63
        10.69.64.64

  - hosts.openshiftprepall

         [cb1avocpm01.le.dp.pcf.local](http://cb1avocpm01.le.dp.pcf.local) 
        cb1avocpm02.le.dp.pcf.local
        cb1avocpm02.le.dp.pcf.local
         [cb1avocpi01.le.dp.pcf.local](http://cb1avocpi01.le.dp.pcf.local) 
        cb1avocpi02.le.dp.pcf.local
        cb1avocpi03.le.dp.pcf.local
        cb1avocpi04.le.dp.pcf.local
        cb1avocpi05.le.dp.pcf.local
         [cb1avocpi06.le.dp.pcf.local](http://cb1avocpi06.le.dp.pcf.local) 
         [cb1avocpa01.le.dp.pcf.local](http://cb1avocpa01.le.dp.pcf.local) 
        cb1avocpa02.le.dp.pcf.local
        cb1avocpa03.le.dp.pcf.local
        cb1avocpa04.le.dp.pcf.local
        cb1ivansn01.le.dp.pcf.local

  - Fix hostname

    sudo nmtui

  - Fix drive for dockervg

        umount /ocp
        nano /etc/fstab
        fdisk /dev/sdb
        d
        w
        lsblk
        df -h
        fdisk -l
        
        #
        # /etc/fstab
        # Created by anaconda on Thu Oct 19 14:35:23 2017
        #
        # Accessible filesystems, by reference, are maintained under '/dev/disk'
        # See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info
        #
        /dev/mapper/rhel-root / xfs defaults 0 0
        UUID=a18efd7e-084c-4e71-9de2-d687f0bcf2d9 /boot xfs defaults 0 0
        /dev/mapper/rhel-home /home xfs defaults 0 0
        # /dev/mapper/rhel-swap swap swap defaults 0 0
        10.69.122.2:/CB1IPOCPN11_NFS500 /ocp nfs defaults 0 0
        # OpenShift-Ansible Installer disabled swap per overcommit guidelines

  - NFS Server Info

    10.69.122.2:/CB1IPOCPN10_NFS500 /ocp nfs defaults 0 0

  - Create OCP Users

        sudo touch /etc/openshift/openshift-passwd
        
        sudo htpasswd /etc/openshift/openshift-passwd ocpdev
        New password:
        Re-type new password:
        
        sudo oadm policy add-cluster-role-to-user admin ocpadmin

  - SDN Networks

        10.69.80.0/22 and 10.69.84.0/22 for the SDN networks

  - OCP AD Integration - Provided by Scalar

        I created the OCP service account and Security Groups. Details as follows:
        ID: svcOCPConnect
        PW: Pc!dm1nOCP@$99
        
        Groups:
        sgOCPAdmin
        sgOCPUsers

- Non-Prod - IDM Build Information - Done in a DOC (PCBank Folder)
  - Note from Aly to Seve - Re - IDM requirements

    I just wanted to kick off the IdM conversation regarding the IdM domain and DNS. All the Linux hosts can remain in their current domain name space ( [pcb.com](http://pcb.com/) ) however the IdM servers themselves will need to live in a dedicated namespace. We normally recommend a subdomain of the current namespace but some client prefer a whole new name space. This is a kerberos requirement and more so when creating trusts with AD. They won't form a trust if they both live in  [pcb.com](http://pcb.com/) .

    A sub-domain like  [nix.pcb.com](http://nix.pcb.com/)  would be ideal space for the IdM servers to live in. If you have already deployed the machines, can adjust this prior to installing IdM but there is also a larger conversation creating and delegating that subdomain in DNS. We can get on a call tomorrow or whenever you like and discuss the high level requirements of deploying IdM so that we can start to prepare them.

    Let me know what works.

  - IdM Build Out —

    Idm Creds

        Admin Passwd: PcBank!2017
        Directory Manager Passwd: w4qHPrSa2y

        Specs
        
        [root@cb1ividmn01 ~]# cat /proc/cpuinfo | grep processor
        processor	: 0
        processor	: 1
        processor	: 2
        processor	: 3
        
        [root@cb1ividmn01 ~]# free -m
         total used free shared buff/cache available
        Mem: 7822 161 6385 8 1275 7329
        Swap: 3967 0 3967
        
        [root@cb1ividmn01 ~]# df -h
        Filesystem Size Used Avail Use% Mounted on
        /dev/mapper/rhel-root 38G 1.9G 36G 5% /
        devtmpfs 3.9G 0 3.9G 0% /dev
        tmpfs 3.9G 0 3.9G 0% /dev/shm
        tmpfs 3.9G 8.5M 3.9G 1% /run
        tmpfs 3.9G 0 3.9G 0% /sys/fs/cgroup
        /dev/sda1 1014M 189M 826M 19% /boot
        /dev/mapper/rhel-home 19G 33M 19G 1% /home
        tmpfs 783M 0 783M 0% /run/user/0
        [root@cb1ividmn01 ~]#
        
        Hostname Update
        [root@cb1ividmn01 ~]# hostname
        cb1ividmn01.le.dp.nix.pcf.local
        [root@cb1ividmn01 ~]#
        SELinux Enabled
        [root@cb1ividmn01 ~]# getenforce 
        Enforcing
        
        IPv6 Enabled
        [root@cb1ividmn01 ~]# ifconfig
        ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
         inet 10.69.120.5 netmask 255.255.255.0 broadcast 10.69.120.255
         inet6 fe80::b9d1:75e6:a9f8:11c3 prefixlen 64 scopeid 0x20<link>
         inet6 fe80::e770:c3fe:74f7:fd10 prefixlen 64 scopeid 0x20<link>
         ether 00:50:56:ad:b8:8c txqueuelen 1000 (Ethernet)
         RX packets 229 bytes 23543 (22.9 KiB)
         RX errors 0 dropped 0 overruns 0 frame 0
         TX packets 160 bytes 18634 (18.1 KiB)
         TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
        
        lo: flags=73<UP,LOOPBACK,RUNNING> mtu 65536
         inet 127.0.0.1 netmask 255.0.0.0
         inet6 ::1 prefixlen 128 scopeid 0x10<host>
         loop txqueuelen 1 (Local Loopback)
         RX packets 64 bytes 5568 (5.4 KiB)
         RX errors 0 dropped 0 overruns 0 frame 0
         TX packets 64 bytes 5568 (5.4 KiB)
         TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
        
        [root@cb1ividmn01 ~]#
        
        DNS
        [root@cb1ividmn01 ~]# cat /etc/resolv.conf 
        # Generated by NetworkManager
        search le.dp.pcf.local le.dp.nix.pcf.local
        nameserver 10.69.120.2
        nameserver 10.69.120.3
        nameserver 10.69.120.4
        [root@cb1ividmn01 ~]#
        
        Validate Initial Lookup
        [root@cb1ividmn01 ~]# nslookup cb1ividmn01.le.dp.pcf.local
        Server:		10.69.120.2
        Address:	10.69.120.2#53
        
        Name:	cb1ividmn01.le.dp.pcf.local
        Address: 10.69.120.5
        
        [root@cb1ividmn01 ~]#
        
        Disable IPtables for now
        [root@cb1ividmn01 ~]# systemctl stop firewalld 
        [root@cb1ividmn01 ~]# iptables -F
        [root@cb1ividmn01 ~]# iptables -L
        Chain INPUT (policy ACCEPT)
        target prot opt source destination 
        
        Chain FORWARD (policy ACCEPT)
        target prot opt source destination 
        
        Chain OUTPUT (policy ACCEPT)
        target prot opt source destination 
        [root@cb1ividmn01 ~]# systemctl disable firewalld
        Removed symlink /etc/systemd/system/multi-user.target.wants/firewalld.service.
        Removed symlink /etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.
        [root@cb1ividmn01 ~]#
        
        Patch System
        [root@cb1ividmn01 ~]# yum update
        Loaded plugins: product-id, search-disabled-repos, subscription-manager
        No packages marked for update
        [root@cb1ividmn01 ~]#
        
        Install IdM Pkgs
        Installed:
        ipa-server.x86_64 0:4.5.0-21.el7_4.2.2 ipa-server-dns.noarch 0:4.5.0-21.el7_4.2.2
        
        [root@cb1ividmn01 ~]# cat /etc/resolv.conf 
        # Generated by NetworkManager
        search le.dp.pcf.local le.dp.nix.pcf.local
        nameserver 10.69.120.2
        nameserver 10.69.120.3
        nameserver 10.69.120.4
        [root@cb1ividmn01 ~]#
        
        >>> Run Build with External CA options
        
        Admin Passwd: PcBank!2017
        Directory Manager Passwd: w4qHPrSa2y
        
        ipa-server-install --mkhomedir --setup-dns --external-ca --external-ca-type=ms-cs
        
        The log file for this installation can be found in /var/log/ipaserver-install.log
        ==============================================================================
        This program will set up the IPA Server.
        
        This includes:
         * Configure a stand-alone CA (dogtag) for certificate management
         * Configure the Network Time Daemon (ntpd)
         * Create and configure an instance of Directory Server
         * Create and configure a Kerberos Key Distribution Center (KDC)
         * Configure Apache (httpd)
         * Configure DNS (bind)
         * Configure the KDC to enable PKINIT
        
        To accept the default shown in brackets, press the Enter key.
        
        WARNING: conflicting time&date synchronization service 'chronyd' willbe disabled
        in favor of ntpd
        
        Enter the fully qualified domain name of the computer
        on which you're setting up server software. Using the form
        <hostname>.<domainname>
        Example: master.example.com.
        
        Server host name [cb1ividmn01.le.dp.nix.pcf.local]: 
        
        Warning: skipping DNS resolution of host cb1ividmn01.le.dp.nix.pcf.local
        The domain name has been determined based on the host name.
        
        Please confirm the domain name [le.dp.nix.pcf.local]: 
        
        The kerberos protocol requires a Realm name to be defined.
        This is typically the domain name converted to uppercase.
        
        Please provide a realm name [LE.DP.NIX.PCF.LOCAL]: 
        Certain directory server operations require an administrative user.
        This user is referred to as the Directory Manager and has full access
        to the Directory for system management tasks and will be added to the
        instance of directory server created for IPA.
        The password must be at least 8 characters long.
        
        Directory Manager password:
        Password (confirm): 
        
        The IPA server requires an administrative user, named 'admin'.
        This user is a regular system account used for IPA server administration.
        
        IPA admin password: 
        Password (confirm): 
        
        Checking DNS domain le.dp.nix.pcf.local., please wait ...
        Do you want to configure DNS forwarders? [yes]: no
        No DNS forwarders configured
        Do you want to search for missing reverse zones? [yes]: no
        
        The IPA Master Server will be configured with:
        Hostname: cb1ividmn01.le.dp.nix.pcf.local
        IP address(es): 10.69.120.5
        Domain name: le.dp.nix.pcf.local
        Realm name: LE.DP.NIX.PCF.LOCAL
        
        BIND DNS server will be configured to serve IPA domain with:
        Forwarders: No forwarders
        Forward policy: only
        Reverse zone(s): No reverse zone
        
        Continue to configure the system with these values? [no]:yes
        
        The following operations may take some minutes to complete.
        Please wait until the prompt is returned.
        
        Adding [10.69.120.5 cb1ividmn01.le.dp.nix.pcf.local to your /etc/hosts file
        Configuring NTP daemon (ntpd)
         [1/4]: stopping ntpd
         [2/4]: writing configuration
         [3/4]: configuring ntpd to start on boot
         [4/4]: starting ntpd
        Done configuring NTP daemon (ntpd).
        Configuring directory server (dirsrv). Estimated time: 30 seconds
         [1/45]: creating directory server instance
         [2/45]: enabling ldapi
         [3/45]: configure autobind for root
         [4/45]: stopping directory server
         [5/45]: updating configuration in dse.ldif
         [6/45]: starting directory server
         [7/45]: adding default schema
         [8/45]: enabling memberof plugin
         [9/45]: enabling winsync plugin
         [10/45]: configuring replication version plugin
         [11/45]: enabling IPA enrollment plugin
         [12/45]: configuring uniqueness plugin
         [13/45]: configuring uuid plugin
         [14/45]: configuring modrdn plugin
         [15/45]: configuring DNS plugin
         [16/45]: enabling entryUSN plugin
         [17/45]: configuring lockout plugin
         [18/45]: configuring topology plugin
         [19/45]: creating indices
         [20/45]: enabling referential integrity plugin
         [21/45]: configuring certmap.conf
         [22/45]: configure new location for managed entries
         [23/45]: configure dirsrv ccache
         [24/45]: enabling SASL mapping fallback
         [25/45]: restarting directory server
         [26/45]: adding sasl mappings to the directory
         [27/45]: adding default layout
         [28/45]: adding delegation layout
         [29/45]: creating container for managed entries
         [30/45]: configuring user private groups
         [31/45]: configuring netgroups from hostgroups
         [32/45]: creating default Sudo bind user
         [33/45]: creating default Auto Member layout
         [34/45]: adding range check plugin
         [35/45]: creating default HBAC rule allow_all
         [36/45]: adding entries for topology management
         [37/45]: initializing group membership
         [38/45]: adding master entry
         [39/45]: initializing domain level
         [40/45]: configuring Posix uid/gid generation
         [41/45]: adding replication acis
         [42/45]: activating sidgen plugin
         [43/45]: activating extdom plugin
         [44/45]: tuning directory server
         [45/45]: cofiguring directory to start on boot
        Done configuring directory server (dirsrv).
        Configuring Kerberos KDC (krb5kdc)
         [1/10]: adding kerberos container to the directory
         [2/10]: configuring KDC
         [3/10]: initialize kerberos container
         [4/10]: adding default ACI
         [5/10]: creating a keytab for the directory
         [6/10]: creating a keytab for the machine
         [7/10]: adding the password extension to the directory
         [8/10]: creating anonymous principal
         [9/10]: starting the KDC
         [10/10]: configuring KDC to start on boot
        Done configuring Kerberos KDC (krb5kdc).
        Configuring kadmin
         [1/2]: starting kadmin 
         [2/2]: configuring kadmin to start on boot
        Done configuring kadmin.
        Configuring certificate server (pki-tomcatd). Estimated time: 3 minutes
         [1/8]: configuring certificate server instance
        The next step is to get /root/ipa.csr signed by your CA and re-run /usr/sbin/ipa-server-install as:
        /usr/sbin/ipa-server-install --external-cert-file=/path/to/signed_certificate --external-cert-file=/path/to/external_ca_certificate
        [root@cb1ividmn01 ~]#
        
        [root@cb1ividmn01 ~]# cat /root/ipa.csr
        -----BEGIN NEW CERTIFICATE REQUEST-----
        MIIC0DCCAbgCAQAwPjEcMBoGA1UEChMTTEUuRFAuTklYLlBDRi5MT0NBTDEeMBwG
        A1UEAxMVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOC
        AQ8AMIIBCgKCAQEAvNe223HNvok2I1V8XOHNEZPzgKDKnrWJ2+d1mRCPB0NSbqB1
        pztfpCDQ5J1bt7bxku+7gCE1ztr4/hJsm7PjC+i7v5hR5k4CsNdOd70ICyzK7KUS
        CkOxunlSETyQe2LllSSlYykZ6riKWjJQdEZfgBatOYNhKqcYu+wruR+C87ZCbAhm
        /XnKs/Avo/M4qWD5olSdutGqkZSSno7QWCFEEEt2SGS2Re9FHTzMB0WFpyw6dy65
        sdqCxwPOSUptelsRDepiCkUX+8ELTaOhLez9jqS5tIcRIYIlOeX8H/KsW/KSvcGj
        o8Q3fxvlEB+rr4rAk9L6zfFEQDsiTOYQc5Z9VwIDAQABoE0wSwYJKoZIhvcNAQkO
        MT4wPDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAPBgNVHRMBAf8EBTADAQH/
        MA4GA1UdDwEB/wQEAwIBxjANBgkqhkiG9w0BAQsFAAOCAQEAqYIK6ugoQjNFiG01
        Y+yf/9X7BS7LCdklNVKFoTCZIFKLiRx4u9TLQJAToXcQ9rQBkS5LVOWJRRER6i9j
        M16fqB+eZog8n6+1e07v5j0xWcmlmUYZ8L58LQp53S1Kofd9ms/fCnpSIw3W3sqC
        5cgO3589037lrOJwP3CuC0BP60yobNUUnP8838BfPf5G15m0uil6G/cZwwMQwTCL
        hKSCc44DQ9n3SyOz9sjVWJ8qNB5BkBKZka9HTWa+qs/wdOmhBa+arjb5G/Hgd1BE
        URb7s/PBkURjxVuAAcsP+eV298r1mMiDs6b8IBUd0akG8/Oe/pdt2r23G4ch/S0s
        COuFHQ==
        -----END NEW CERTIFICATE REQUEST-----
        [root@cb1ividmn01 ~]#
        
        >>>> Signed Certs Returned By Emmett
        
        [root@cb1ividmn01 certs]# ipa-server-install --external-cert-file=/root/certs/cert-cb1ividmn01-new.cer --external-cert-file=/root/certs/NPRODROOTCA.cer
        
        The log file for this installation can be found in /var/log/ipaserver-install.log
        Directory Manager password: 
        
        ==============================================================================
        This program will set up the IPA Server.
        
        This includes:
         * Configure a stand-alone CA (dogtag) for certificate management
         * Configure the Network Time Daemon (ntpd)
         * Create and configure an instance of Directory Server
         * Create and configure a Kerberos Key Distribution Center (KDC)
         * Configure Apache (httpd)
         * Configure DNS (bind)
         * Configure the KDC to enable PKINIT
        
        Warning: skipping DNS resolution of host cb1ividmn01.le.dp.nix.pcf.local
        Checking DNS domain le.dp.nix.pcf.local., please wait ...
        Do you want to configure DNS forwarders? [yes]: no
        No DNS forwarders configured
        
        The IPA Master Server will be configured with:
        Hostname: cb1ividmn01.le.dp.nix.pcf.local
        IP address(es): 10.69.120.5
        Domain name: le.dp.nix.pcf.local
        Realm name: LE.DP.NIX.PCF.LOCAL
        
        BIND DNS server will be configured to serve IPA domain with:
        Forwarders: No forwarders
        Forward policy: only
        Reverse zone(s): No reverse zone
        
        Configuring certificate server (pki-tomcatd). Estimated time: 3 minutes
         [1/29]: configuring certificate server instance
         [2/29]: exporting Dogtag certificate store pin
         [3/29]: stopping certificate server instance to update CS.cfg
         [4/29]: backing up CS.cfg
         [5/29]: disabling nonces
         [6/29]: set up CRL publishing
         [7/29]: enable PKIX certificate path discovery and validation
         [8/29]: starting certificate server instance
         [9/29]: configure certmonger for renewals
         [10/29]: requesting RA certificate from CA
         [11/29]: setting up signing cert profile
         [12/29]: setting audit signing renewal to 2 years
         [13/29]: restarting certificate server
         [14/29]: publishing the CA certificate
         [15/29]: adding RA agent as a trusted user
         [16/29]: authorizing RA to modify profiles
         [17/29]: authorizing RA to manage lightweight CAs
         [18/29]: Ensure lightweight CAs container exists
         [19/29]: configure certificate renewals
         [20/29]: configure Server-Cert certificate renewal
         [21/29]: Configure HTTP to proxy connections
         [22/29]: restarting certificate server
         [23/29]: updating IPA configuration
         [24/29]: enabling CA instance
         [25/29]: migrating certificate profiles to LDAP
         [26/29]: importing IPA certificate profiles
         [27/29]: adding default CA ACL
         [28/29]: adding 'ipa' CA entry
         [29/29]: configuring certmonger renewal for lightweight CAs
        Done configuring certificate server (pki-tomcatd).
        Configuring directory server (dirsrv)
         [1/3]: configuring TLS for DS instance
         [2/3]: adding CA certificate entry
         [3/3]: restarting directory server
        Done configuring directory server (dirsrv).
        Configuring ipa-otpd
         [1/2]: starting ipa-otpd 
         [2/2]: configuring ipa-otpd to start on boot
        Done configuring ipa-otpd.
        Configuring ipa-custodia
         [1/5]: Generating ipa-custodia config file
         [2/5]: Making sure custodia container exists
         [3/5]: Generating ipa-custodia keys
         [4/5]: starting ipa-custodia 
         [5/5]: configuring ipa-custodia to start on boot
        Done configuring ipa-custodia.
        Configuring the web interface (httpd)
         [1/22]: stopping httpd
         [2/22]: setting mod_nss port to 443
         [3/22]: setting mod_nss cipher suite
         [4/22]: setting mod_nss protocol list to TLSv1.0 - TLSv1.2
         [5/22]: setting mod_nss password file
         [6/22]: enabling mod_nss renegotiate
         [7/22]: disabling mod_nss OCSP
         [8/22]: adding URL rewriting rules
         [9/22]: configuring httpd
         [10/22]: setting up httpd keytab
         [11/22]: configuring Gssproxy
         [12/22]: setting up ssl
         [13/22]: configure certmonger for renewals
         [14/22]: importing CA certificates from LDAP
         [15/22]: publish CA cert
         [16/22]: clean up any existing httpd ccaches
         [17/22]: configuring SELinux for httpd
         [18/22]: create KDC proxy config
         [19/22]: enable KDC proxy
         [20/22]: starting httpd
         [21/22]: configuring httpd to start on boot
         [22/22]: enabling oddjobd
        Done configuring the web interface (httpd).
        Configuring Kerberos KDC (krb5kdc)
         [1/1]: installing X509 Certificate for PKINIT
        Done configuring Kerberos KDC (krb5kdc).
        Applying LDAP updates
        
        Upgrading IPA:. Estimated time: 1 minute 30 seconds
         [1/9]: stopping directory server
         [2/9]: saving configuration
         [3/9]: disabling listeners
         [4/9]: enabling DS global lock
         [5/9]: starting directory server
         [6/9]: upgrading server
         [7/9]: stopping directory server
         [8/9]: restoring configuration
         [9/9]: starting directory server
        Done.
        Restarting the KDC
        Configuring DNS (named)
         [1/11]: generating rndc key file
         [2/11]: adding DNS container
         [3/11]: setting up our zone
         [4/11]: setting up our own record
         [5/11]: setting up records for other masters
         [6/11]: adding NS record to the zones
         [7/11]: setting up kerberos principal
         [8/11]: setting up named.conf
         [9/11]: setting up server configuration
         [10/11]: configuring named to start on boot
         [11/11]: changing resolv.conf to point to ourselves
        Done configuring DNS (named).
        Restarting the web server to pick up resolv.conf changes
        Configuring DNS key synchronization service (ipa-dnskeysyncd)
         [1/7]: checking status
         [2/7]: setting up bind-dyndb-ldap working directory
         [3/7]: setting up kerberos principal
         [4/7]: setting up SoftHSM
         [5/7]: adding DNSSEC containers
         [6/7]: creating replica keys
         [7/7]: configuring ipa-dnskeysyncd to start on boot
        Done configuring DNS key synchronization service (ipa-dnskeysyncd).
        Restarting ipa-dnskeysyncd
        Restarting named
        Updating DNS system records
        Configuring client side components
        Using existing certificate '/etc/ipa/ca.crt'.
        Client hostname: cb1ividmn01.le.dp.nix.pcf.local
        Realm: LE.DP.NIX.PCF.LOCAL
        DNS Domain: le.dp.nix.pcf.local
        IPA Server: cb1ividmn01.le.dp.nix.pcf.local
        BaseDN: dc=le,dc=dp,dc=nix,dc=pcf,dc=local
        
        Skipping synchronizing time with NTP server.
        New SSSD config will be created
        Configured sudoers in /etc/nsswitch.conf
        Configured /etc/sssd/sssd.conf
        trying https://cb1ividmn01.le.dp.nix.pcf.local/ipa/json
        [try 1]: Forwarding 'schema' to json server 'https://cb1ividmn01.le.dp.nix.pcf.local/ipa/json'
        trying https://cb1ividmn01.le.dp.nix.pcf.local/ipa/session/json
        [try 1]: Forwarding 'ping' to json server 'https://cb1ividmn01.le.dp.nix.pcf.local/ipa/session/json'
        [try 1]: Forwarding 'ca_is_enabled' to json server 'https://cb1ividmn01.le.dp.nix.pcf.local/ipa/session/json'
        Systemwide CA database updated.
        Adding SSH public key from /etc/ssh/ssh_host_rsa_key.pub
        Adding SSH public key from /etc/ssh/ssh_host_ecdsa_key.pub
        Adding SSH public key from /etc/ssh/ssh_host_ed25519_key.pub
        [try 1]: Forwarding 'host_mod' to json server 'https://cb1ividmn01.le.dp.nix.pcf.local/ipa/session/json'
        SSSD enabled
        Configured /etc/openldap/ldap.conf
        Configured /etc/ssh/ssh_config
        Configured /etc/ssh/sshd_config
        Configuring le.dp.nix.pcf.local as NIS domain.
        Client configuration complete.
        The ipa-client-install command was successful
        
        ==============================================================================
        Setup complete
        
        Next steps:
        	1. You must make sure these network ports are open:
        		TCP Ports:
        		 * 80, 443: HTTP/HTTPS
        		 * 389, 636: LDAP/LDAPS
        		 * 88, 464: kerberos
        		 * 53: bind
        		UDP Ports:
        		 * 88, 464: kerberos
        		 * 53: bind
        		 * 123: ntp
        
        	2. You can now obtain a kerberos ticket using the command: 'kinit admin'
        	 This ticket will allow you to use the IPA tools (e.g., ipa user-add)
        	 and the web user interface.
        
        Be sure to back up the CA certificates stored in /root/cacert.p12
        These files are required to create replicas. The password for these
        files is the Directory Manager password
        [root@cb1ividmn01 certs]#
        
        >>>>> Testing
        [root@cb1ividmn01 certs]# id admin
        uid=1856200000(admin) gid=1856200000(admins) groups=1856200000(admins)
        
        [root@cb1ividmn01 certs]# klist
        klist: Credentials cache keyring 'persistent:0:0' not found
        
        [root@cb1ividmn01 certs]# kinit admin
        Password for admin@LE.DP.NIX.PCF.LOCAL: 
        [root@cb1ividmn01 certs]# klist
        Ticket cache: KEYRING:persistent:0:0
        Default principal: admin@LE.DP.NIX.PCF.LOCAL
        
        Valid starting Expires Service principal
        21/11/17 13:50:37 22/11/17 13:50:17 krbtgt/LE.DP.NIX.PCF.LOCAL@LE.DP.NIX.PCF.LOCAL
        [root@cb1ividmn01 certs]#
        
        [root@cb1ividmn01 certs]# ldapsearch -x uid=admin
        # extended LDIF
        #
        # LDAPv3
        # base <dc=le,dc=dp,dc=nix,dc=pcf,dc=local> (default) with scope subtree
        # filter: uid=admin
        # requesting: ALL
        #
        
        # admin, users, compat, le.dp.nix.pcf.local
        dn: uid=admin,cn=users,cn=compat,dc=le,dc=dp,dc=nix,dc=pcf,dc=local
        objectClass: posixAccount
        objectClass: ipaOverrideTarget
        objectClass: top
        gecos: Administrator
        cn: Administrator
        uidNumber: 1856200000
        gidNumber: 1856200000
        loginShell: /bin/bash
        homeDirectory: /home/admin
        ipaAnchorUUID:: OklQQTpsZS5kcC5uaXgucGNmLmxvY2FsOjkxN2NlMzI2LWNiYWItMTFlNy1iOW
         NmLTAwNTA1NmFkYjg4Yw==
        uid: admin
        
        # admin, users, accounts, le.dp.nix.pcf.local
        dn: uid=admin,cn=users,cn=accounts,dc=le,dc=dp,dc=nix,dc=pcf,dc=local
        objectClass: top
        objectClass: person
        objectClass: posixaccount
        objectClass: krbprincipalaux
        objectClass: krbticketpolicyaux
        objectClass: inetuser
        objectClass: ipaobject
        objectClass: ipasshuser
        objectClass: ipaSshGroupOfPubKeys
        uid: admin
        cn: Administrator
        sn: Administrator
        uidNumber: 1856200000
        gidNumber: 1856200000
        homeDirectory: /home/admin
        loginShell: /bin/bash
        gecos: Administrator
        
        # search result
        search: 2
        result: 0 Success
        
        # numResponses: 3
        # numEntries: 2

    IdM02

        [root@cb1ividmn02 ~]# cat /proc/cpuinfo | grep processor
        processor	: 0
        processor	: 1
        processor	: 
        processor	: 3
        
        [root@cb1ividmn02 ~]# free -m
         total used free shared buff/cache available
        Mem: 7822 170 7437 8 214 7390
        Swap: 3967 0 3967
        
        [root@cb1ividmn02 ~]# df -h
        Filesystem Size Used Avail Use% Mounted on
        /dev/mapper/rhel-root 38G 1.3G 36G 4% /
        devtmpfs 3.9G 0 3.9G 0% /dev
        tmpfs 3.9G 0 3.9G 0% /dev/shm
        tmpfs 3.9G 8.5M 3.9G 1% /run
        tmpfs 3.9G 0 3.9G 0% /sys/fs/cgroup
        /dev/mapper/rhel-home 19G 33M 19G 1% /home
        /dev/sda1 1014M 189M 826M 19% /boot
        tmpfs 783M 0 783M 0% /run/user/0
        
        [root@cb1ividmn02 ~]# hostname
         [cb1ividmn02.le.dp.nix.pcf.local](http://cb1ividmn02.le.dp.nix.pcf.local) 
        
        [root@cb1ividmn02 ~]# getenforce 
        Enforcing
        
        [root@cb1ividmn02 ~]# ifconfig
        ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
         inet 10.69.120.6 netmask 255.255.255.0 broadcast 10.69.120.255
         inet6 fe80::b290:5f2b:4124:991b prefixlen 64 scopeid 0x20<link>
         inet6 fe80::b9d1:75e6:a9f8:11c3 prefixlen 64 scopeid 0x20<link>
         inet6 fe80::e770:c3fe:74f7:fd10 prefixlen 64 scopeid 0x20<link>
         ether 00:50:56:ad:52:38 txqueuelen 1000 (Ethernet)
         RX packets 180 bytes 18081 (17.6 KiB)
         RX errors 0 dropped 0 overruns 0 frame 0
         TX packets 135 bytes 16155 (15.7 KiB)
         TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
        
        lo: flags=73<UP,LOOPBACK,RUNNING> mtu 65536
         inet 127.0.0.1 netmask 255.0.0.0
         inet6 ::1 prefixlen 128 scopeid 0x10<host>
         loop txqueuelen 1 (Local Loopback)
         RX packets 64 bytes 5568 (5.4 KiB)
         RX errors 0 dropped 0 overruns 0 frame 0
         TX packets 64 bytes 5568 (5.4 KiB)
         TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
        
        [root@cb1ividmn02 ~]#
        [root@cb1ividmn02 ~]# systemctl disable firewalld
        Removed symlink /etc/systemd/system/multi-user.target.wants/firewalld.service.
        Removed symlink /etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.
        [root@cb1ividmn02 ~]# iptables -F
        
        >>> Patch
        Fully Patched
        
        >>> Install IdM Packages
        Installed:
        ipa-server.x86_64 0:4.5.0-21.el7_4.2.2 ipa-server-dns.noarch 0:4.5.0-21.el7_4.2.2
        
        >>> Install Replica
        
        [root@cb1ividmn02 ~]# ipa-replica-install --principal admin --admin-password 'PcBank!2017' --setup-dns --setup-ca --no-forwarders
        WARNING: conflicting time&date synchronization service 'chronyd' will
        be disabled in favor of ntpd
        
        Configuring client side components
        Discovery was successful!
        Client hostname: cb1ividmn02.le.dp.nix.pcf.local
        Realm: LE.DP.NIX.PCF.LOCAL
        DNS Domain: le.dp.nix.pcf.local
        IPA Server: cb1ividmn01.le.dp.nix.pcf.local
        BaseDN: dc=le,dc=dp,dc=nix,dc=pcf,dc=local
        
        Skipping synchronizing time with NTP server.
        Successfully retrieved CA cert
         Subject: CN=NPRODROOTCA1
         Issuer: CN=NPRODROOTCA1
         Valid From: 2017-11-16 22:26:42
         Valid Until: 2027-11-16 22:36:42
        
         Subject: CN=Certificate Authority,O=LE.DP.NIX.PCF.LOCAL
         Issuer: CN=NPRODROOTCA1
         Valid From: 2017-11-20 14:59:26
         Valid Until: 2023-11-20 15:09:26
        
        Enrolled in IPA realm LE.DP.NIX.PCF.LOCAL
        Created /etc/ipa/default.conf
        New SSSD config will be created
        Configured sudoers in /etc/nsswitch.conf
        Configured /etc/sssd/sssd.conf
        Configured /etc/krb5.conf for IPA realm LE.DP.NIX.PCF.LOCAL
        trying https://cb1ividmn01.le.dp.nix.pcf.local/ipa/json
        [try 1]: Forwarding 'ping' to json server 'https://cb1ividmn01.le.dp.nix.pcf.local/ipa/json'
        [try 1]: Forwarding 'ca_is_enabled' to json server 'https://cb1ividmn01.le.dp.nix.pcf.local/ipa/json'
        Systemwide CA database updated.
        Adding SSH public key from /etc/ssh/ssh_host_rsa_key.pub
        Adding SSH public key from /etc/ssh/ssh_host_ecdsa_key.pub
        Adding SSH public key from /etc/ssh/ssh_host_ed25519_key.pub
        [try 1]: Forwarding 'host_mod' to json server 'https://cb1ividmn01.le.dp.nix.pcf.local/ipa/json'
        SSSD enabled
        Configured /etc/openldap/ldap.conf
        Configured /etc/ssh/ssh_config
        Configured /etc/ssh/sshd_config
        Configuring le.dp.nix.pcf.local as NIS domain.
        Client configuration complete.
        The ipa-client-install command was successful
        
        ipa : ERROR Reverse DNS resolution of address 10.69.120.5 (cb1ividmn01.le.dp.nix.pcf.local) failed. Clients may not function properly. Please check your DNS setup. (Note that this check queries IPA DNS directly and ignores /etc/hosts.)
        Continue? [no]: yes
        
        Run connection check to master
        Connection check OK
        Configuring NTP daemon (ntpd)
         [1/4]: stopping ntpd
         [2/4]: writing configuration
         [3/4]: configuring ntpd to start on boot
         [4/4]: starting ntpd
        Done configuring NTP daemon (ntpd).
        Configuring directory server (dirsrv). Estimated time: 30 seconds
         [1/40]: creating directory server instance
         [2/40]: enabling ldapi
         [3/40]: configure autobind for root
         [4/40]: stopping directory server
         [5/40]: updating configuration in dse.ldif
         [6/40]: starting directory server
         [7/40]: adding default schema
         [8/40]: enabling memberof plugin
         [9/40]: enabling winsync plugin
         [10/40]: configuring replication version plugin
         [11/40]: enabling IPA enrollment plugin
         [12/40]: configuring uniqueness plugin
         [13/40]: configuring uuid plugin
         [14/40]: configuring modrdn plugin
         [15/40]: configuring DNS plugin
         [16/40]: enabling entryUSN plugin
         [17/40]: configuring lockout plugin
         [18/40]: configuring topology plugin
         [19/40]: creating indices
         [20/40]: enabling referential integrity plugin
         [21/40]: configuring certmap.conf
         [22/40]: configure new location for managed entries
         [23/40]: configure dirsrv ccache
         [24/40]: enabling SASL mapping fallback
         [25/40]: restarting directory server
         [26/40]: creating DS keytab
         [27/40]: setting up initial replication
        Starting replication, please wait until this has completed.
        Update in progress, 3 seconds elapsed
        Update succeeded
         [28/40]: adding sasl mappings to the directory
         [29/40]: updating schema
         [30/40]: setting Auto Member configuration
         [31/40]: enabling S4U2Proxy delegation
         [32/40]: initializing group membership
         [33/40]: adding master entry
         [34/40]: initializing domain level
         [35/40]: configuring Posix uid/gid generation
         [36/40]: adding replication acis
         [37/40]: activating sidgen plugin
         [38/40]: activating extdom plugin
         [39/40]: tuning directory server
         [40/40]: configuring directory to start on boot
        Done configuring directory server (dirsrv).
        Configuring Kerberos KDC (krb5kdc)
         [1/5]: configuring KDC
         [2/5]: adding the password extension to the directory
         [3/5]: creating anonymous principal
         [4/5]: starting the KDC
         [5/5]: configuring KDC to start on boot
        Done configuring Kerberos KDC (krb5kdc).
        Configuring kadmin
         [1/2]: starting kadmin 
         [2/2]: configuring kadmin to start on boot
        Done configuring kadmin.
        Configuring directory server (dirsrv)
         [1/3]: configuring TLS for DS instance
         [2/3]: importing CA certificates from LDAP
         [3/3]: restarting directory server
        Done configuring directory server (dirsrv).
        Configuring the web interface (httpd)
         [1/22]: stopping httpd
         [2/22]: setting mod_nss port to 443
         [3/22]: setting mod_nss cipher suite
         [4/22]: setting mod_nss protocol list to TLSv1.0 - TLSv1.2
         [5/22]: setting mod_nss password file
         [6/22]: enabling mod_nss renegotiate
         [7/22]: disabling mod_nss OCSP
         [8/22]: adding URL rewriting rules
         [9/22]: configuring httpd
         [10/22]: setting up httpd keytab
         [11/22]: configuring Gssproxy
         [12/22]: setting up ssl
         [13/22]: configure certmonger for renewals
         [14/22]: importing CA certificates from LDAP
         [15/22]: publish CA cert
         [16/22]: clean up any existing httpd ccaches
         [17/22]: configuring SELinux for httpd
         [18/22]: create KDC proxy config
         [19/22]: enable KDC proxy
         [20/22]: starting httpd
         [21/22]: configuring httpd to start on boot
         [22/22]: enabling oddjobd
        Done configuring the web interface (httpd).
        Configuring ipa-otpd
         [1/2]: starting ipa-otpd 
         [2/2]: configuring ipa-otpd to start on boot
        Done configuring ipa-otpd.
        Configuring ipa-custodia
         [1/4]: Generating ipa-custodia config file
         [2/4]: Generating ipa-custodia keys
         [3/4]: starting ipa-custodia 
         [4/4]: configuring ipa-custodia to start on boot
        Done configuring ipa-custodia.
        Configuring certificate server (pki-tomcatd). Estimated time: 3 minute
         [1/27]: creating certificate server db
         [2/27]: setting up initial replication
        Starting replication, please wait until this has completed.
        Update in progress, 3 seconds elapsed
        Update succeeded
         [3/27]: creating installation admin user
         [4/27]: configuring certificate server instance
         [5/27]: exporting Dogtag certificate store pin
         [6/27]: stopping certificate server instance to update CS.cfg
         [7/27]: backing up CS.cfg
         [8/27]: disabling nonces
         [9/27]: set up CRL publishing
         [10/27]: enable PKIX certificate path discovery and validation
         [11/27]: destroying installation admin user
         [12/27]: starting certificate server instance
         [13/27]: configure certmonger for renewals
         [14/27]: Importing RA key
         [15/27]: setting up signing cert profile
         [16/27]: setting audit signing renewal to 2 years
         [17/27]: restarting certificate server
         [18/27]: authorizing RA to modify profiles
         [19/27]: authorizing RA to manage lightweight CAs
         [20/27]: Ensure lightweight CAs container exists
         [21/27]: configure certificate renewals
         [22/27]: configure Server-Cert certificate renewal
         [23/27]: Configure HTTP to proxy connections
         [24/27]: restarting certificate server
         [25/27]: updating IPA configuration
         [26/27]: enabling CA instance
         [27/27]: configuring certmonger renewal for lightweight CAs
        Done configuring certificate server (pki-tomcatd).
        Configuring Kerberos KDC (krb5kdc)
         [1/1]: installing X509 Certificate for PKINIT
        Done configuring Kerberos KDC (krb5kdc).
        Applying LDAP updates
        Upgrading IPA:. Estimated time: 1 minute 30 seconds
         [1/9]: stopping directory server
         [2/9]: saving configuration
         [3/9]: disabling listeners
         [4/9]: enabling DS global lock
         [5/9]: starting directory server
         [6/9]: upgrading server
         [7/9]: stopping directory server
         [8/9]: restoring configuration
         [9/9]: starting directory server
        Done.
        Restarting the KDC
        Configuring DNS (named)
         [1/8]: generating rndc key file
         [2/8]: setting up our own record
         [3/8]: adding NS record to the zones
         [4/8]: setting up kerberos principal
         [5/8]: setting up named.conf
         [6/8]: setting up server configuration
         [7/8]: configuring named to start on boot
         [8/8]: changing resolv.conf to point to ourselves
        Done configuring DNS (named).
        Restarting the web server to pick up resolv.conf changes
        Configuring DNS key synchronization service (ipa-dnskeysyncd)
         [1/7]: checking status
         [2/7]: setting up bind-dyndb-ldap working directory
         [3/7]: setting up kerberos principal
         [4/7]: setting up SoftHSM
         [5/7]: adding DNSSEC containers
         [6/7]: creating replica keys
         [7/7]: configuring ipa-dnskeysyncd to start on boot
        Done configuring DNS key synchronization service (ipa-dnskeysyncd).
        Restarting ipa-dnskeysyncd
        Restarting named
        Updating DNS system records
        
        Global DNS configuration in LDAP server is empty
        You can use 'dnsconfig-mod' command to set global DNS options that
        would override settings in local named.conf files
        
        >>> Validate
        [root@cb1ividmn02 ~]# cat /etc/resolv.conf 
        search le.dp.nix.pcf.local
        nameserver 127.0.0.1
        
        [root@cb1ividmn02 ~]# id admin
        uid=1856200000(admin) gid=1856200000(admins) groups=1856200000(admins)
        
        [root@cb1ividmn02 ~]# kinit admin
        Password for admin@LE.DP.NIX.PCF.LOCAL: 
        
        [root@cb1ividmn02 ~]# klist
        Ticket cache: KEYRING:persistent:0:0
        Default principal: admin@LE.DP.NIX.PCF.LOCAL
        
        Valid starting Expires Service principal
        21/11/17 14:37:36 22/11/17 14:37:31 krbtgt/LE.DP.NIX.PCF.LOCAL@LE.DP.NIX.PCF.LOCAL
        [root@cb1ividmn02 ~]#
        
        [root@cb1ividmn02 ~]# ldapsearch -x uid=admin
        # extended LDIF
        #
        # LDAPv3
        # base <dc=le,dc=dp,dc=nix,dc=pcf,dc=local> (default) with scope subtree
        # filter: uid=admin
        # requesting: ALL
        #
        
        # admin, users, compat, le.dp.nix.pcf.local
        dn: uid=admin,cn=users,cn=compat,dc=le,dc=dp,dc=nix,dc=pcf,dc=local
        objectClass: posixAccount
        objectClass: ipaOverrideTarget
        objectClass: top
        gecos: Administrator
        cn: Administrator
        uidNumber: 1856200000
        gidNumber: 1856200000
        loginShell: /bin/bash
        homeDirectory: /home/admin
        ipaAnchorUUID:: OklQQTpsZS5kcC5uaXgucGNmLmxvY2FsOjkxN2NlMzI2LWNiYWItMTFlNy1iOW
         NmLTAwNTA1NmFkYjg4Yw==
        uid: admin
        
        # admin, users, accounts, le.dp.nix.pcf.local
        dn: uid=admin,cn=users,cn=accounts,dc=le,dc=dp,dc=nix,dc=pcf,dc=local
        gecos: Administrator
        loginShell: /bin/bash
        homeDirectory: /home/admin
        gidNumber: 1856200000
        uidNumber: 1856200000
        sn: Administrator
        cn: Administrator
        uid: admin
        objectClass: top
        objectClass: person
        objectClass: posixaccount
        objectClass: krbprincipalaux
        objectClass: krbticketpolicyaux
        objectClass: inetuser
        objectClass: ipaobject
        objectClass: ipasshuser
        objectClass: ipaSshGroupOfPubKeys
        
        # search result
        search: 2
        result: 0 Success
        
        # numResponses: 3
        # numEntries: 2
        [root@cb1ividmn02 ~]#

    Base Complete

        [root@cb1ividmn02 ~]# ipa-replica-manage list
        cb1ividmn02.le.dp.nix.pcf.local: master
        cb1ividmn01.le.dp.nix.pcf.local: master
        [root@cb1ividmn02 ~]#
        
        [root@cb1ividmn02 ~]# ipa-csreplica-manage list
        Directory Manager password: 
        
        cb1ividmn02.le.dp.nix.pcf.local: master
        cb1ividmn01.le.dp.nix.pcf.local: master
        [root@cb1ividmn02 ~]#
        
        >>> Forward to Zone Lookup to [ [le.dp.pcf.local](http://le.dp.pcf.local) ]
        
        [root@cb1ividmn01 certs]# nslookup cb1ivansn01.le.dp.pcf.local
        Server:		127.0.0.1
        Address:	127.0.0.1#53
        
        Non-authoritative answer:
        Name:	cb1ivansn01.le.dp.pcf.local
        Address: 10.69.65.2
        
        [root@cb1ividmn01 certs]#
        
        [root@cb1ividmn02 ~]# nslookup cb1ivansn01.le.dp.pcf.local
        Server:		127.0.0.1
        Address:	127.0.0.1#53
        
        Non-authoritative answer:
        Name:	cb1ivansn01.le.dp.pcf.local
        Address: 10.69.65.2
        
        [root@cb1ividmn02 ~]#
        
        

    Topology Graph

    ![](https://static.notion-static.com/742af35a0bca4c60b6cd7bc0d0112943/Screen_Shot_2017-11-21_at_2.55.09_PM.png)

        >>> Test User Login
        [root@cb1ividmn02 ~]# ssh test01@localhost
        The authenticity of host 'localhost (<no hostip for proxy command>)' can't be established.
        ECDSA key fingerprint is SHA256:KdfA9i0rNHEaqK5hz6jgPBoFM8roMXslkp2fmTO2KSM.
        ECDSA key fingerprint is MD5:be:1e:f4:36:d5:11:47:f8:d9:7f:f3:8a:ac:16:7b:c8.
        Are you sure you want to continue connecting (yes/no)? yes
        Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
        
        Password: 
        Last login: Tue Nov 21 14:58:20 2017
        Could not chdir to home directory /home/test01: No such file or directory
        
        -sh-4.2$ id
        uid=1856200001(test01) gid=1856200001(test01) groups=1856200001(test01) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
        
        -sh-4.2$ whoami
        test01
        
        -sh-4.2$ klist
        Ticket cache: KEYRING:persistent:1856200001:krb_ccache_47dadrv
        Default principal: test01@LE.DP.NIX.PCF.LOCAL
        
        Valid starting Expires Service principal
        21/11/17 14:58:36 22/11/17 14:58:36 krbtgt/LE.DP.NIX.PCF.LOCAL@LE.DP.NIX.PCF.LOCAL
        -sh-4.2$

    DNS Validation

        IdM - Pre AD pkgs
        [root@cb1ividmn01 ~]# ./dns-idm.sh 
        Searching: cb1ividmn01 A Records 
        cb1ividmn01.le.dp.nix.pcf.local. 1200 IN A 10.69.120.5
        
        Searching: cb1ividmn02 A Records 
        cb1ividmn02.le.dp.nix.pcf.local. 1200 IN A 10.69.120.6
        
        Searching: ipa-ca Records 
        ipa-ca.le.dp.nix.pcf.local. 86400 IN A 10.69.120.6 ipa-ca.le.dp.nix.pcf.local. 86400 IN A 10.69.120.5
        
        Searching: TXT; 
        _kerberos.le.dp.nix.pcf.local. 86400 IN	TXT	"LE.DP.NIX.PCF.LOCAL"
        
        Searching: _ldap._tcp; 
        _ldap._tcp.le.dp.nix.pcf.local.	86400 IN SRV	0 100 389 cb1ividmn01.le.dp.nix.pcf.local.
        _ldap._tcp.le.dp.nix.pcf.local.	86400 IN SRV	0 100 389 cb1ividmn02.le.dp.nix.pcf.local.
        
        Searching: _kerberos._tcp
        _kerberos._tcp.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        _kerberos._tcp.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _kerberos._udp
        _kerberos._udp.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        _kerberos._udp.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _kerberos-master._tcp
        _kerberos-master._tcp.le.dp.nix.pcf.local. 86400 IN SRV	0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        _kerberos-master._tcp.le.dp.nix.pcf.local. 86400 IN SRV	0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _kerberos-master._udp
        _kerberos-master._udp.le.dp.nix.pcf.local. 86400 IN SRV	0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        _kerberos-master._udp.le.dp.nix.pcf.local. 86400 IN SRV	0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _ntp._udp
        _ntp._udp.le.dp.nix.pcf.local. 86400 IN	SRV	0 100 123 cb1ividmn01.le.dp.nix.pcf.local.
        _ntp._udp.le.dp.nix.pcf.local. 86400 IN	SRV	0 100 123 cb1ividmn02.le.dp.nix.pcf.local.
        
        Searching: _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs
        
        Searching: _kerberos._udp.Default-First-Site-Name._sites.dc._msdcs
        
        Searching: _kerberos._tcp.dc._msdcs
        
        Searching: _ldap._tcp.dc._msdcs
        
        IdM -> AD
        [root@cb1ividmn01 ~]# ./dns-ad.sh 
        Searching: CB1IVDCN01 A Records 
        CB1IVDCN01.pcf.local. 3092 IN A 10.69.120.2
        
        Searching: CB1IVDCN02 A Records 
        CB1IVDCN02.pcf.local. 3092 IN A 10.69.120.3
        
        Searching: CB1IVDCN03 A Records 
        CB1IVDCN03.pcf.local. 3092 IN A 10.69.120.4
        
        Searching: TXT; 
        
        Searching: _ldap._tcp; 
        _ldap._tcp.pcf.local.	27	IN	SRV	0 100 389 cb1ivdcn02.pcf.local.
        _ldap._tcp.pcf.local.	27	IN	SRV	0 100 389 CB1IVDCN01.pcf.local.
        _ldap._tcp.pcf.local.	27	IN	SRV	0 100 389 CB1IVDCN03.pcf.local.
        
        Searching: _kerberos._tcp
        _kerberos._tcp.pcf.local. 27	IN	SRV	0 100 88 CB1IVDCN01.pcf.local.
        _kerberos._tcp.pcf.local. 27	IN	SRV	0 100 88 cb1ivdcn02.pcf.local.
        _kerberos._tcp.pcf.local. 27	IN	SRV	0 100 88 CB1IVDCN03.pcf.local.
        
        Searching: _kerberos._udp
        _kerberos._udp.pcf.local. 27	IN	SRV	0 100 88 CB1IVDCN03.pcf.local.
        _kerberos._udp.pcf.local. 27	IN	SRV	0 100 88 CB1IVDCN01.pcf.local.
        _kerberos._udp.pcf.local. 27	IN	SRV	0 100 88 cb1ivdcn02.pcf.local.
        
        Searching: _kerberos-master._tcp
        
        Searching: _kerberos-master._udp
        
        Searching: _ntp._udp
        
        Searching: _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs
        _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.pcf.local. 27 IN SRV 0 100 389 CB1IVDCN03.pcf.local.
        _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.pcf.local. 27 IN SRV 0 100 389 cb1ivdcn02.pcf.local.
        _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.pcf.local. 27 IN SRV 0 100 389 CB1IVDCN01.pcf.local.
        
        Searching: _kerberos._udp.Default-First-Site-Name._sites.dc._msdcs
        
        Searching: _kerberos._tcp.dc._msdcs
        _kerberos._tcp.dc._msdcs.pcf.local. 27 IN SRV	0 100 88 CB1IVDCN03.pcf.local.
        _kerberos._tcp.dc._msdcs.pcf.local. 27 IN SRV	0 100 88 cb1ivdcn02.pcf.local.
        _kerberos._tcp.dc._msdcs.pcf.local. 27 IN SRV	0 100 88 CB1IVDCN01.pcf.local.
        
        Searching: _ldap._tcp.dc._msdcs
        _ldap._tcp.dc._msdcs.pcf.local.	27 IN	SRV	0 100 389 CB1IVDCN03.pcb.com.
        _ldap._tcp.dc._msdcs.pcf.local.	27 IN	SRV	0 100 389 CB1IVDCN01.pcf.local.
        _ldap._tcp.dc._msdcs.pcf.local.	27 IN	SRV	0 100 389 CB1IVDCN03.pcf.local.
        _ldap._tcp.dc._msdcs.pcf.local.	27 IN	SRV	0 100 389 cb1ivdcn02.pcf.local.

    Prep AD-pkgs

        Installed:
         ipa-server-trust-ad.x86_64 0:4.5.0-21.el7_4.2.2 
        
        Dependency Installed:
         pyldb.x86_64 0:1.1.29-1.el7 pytalloc.x86_64 0:2.1.9-1.el7 python-libsss_nss_idmap.x86_64 0:1.15.2-50.el7_4.6 python-sss.x86_64 0:1.15.2-50.el7_4.6 python-tdb.x86_64 0:1.3.12-2.el7 
         python-tevent.x86_64 0:0.9.31-1.el7 samba.x86_64 0:4.6.2-11.el7_4 samba-common-libs.x86_64 0:4.6.2-11.el7_4 samba-common-tools.x86_64 0:4.6.2-11.el7_4 samba-libs.x86_64 0:4.6.2-11.el7_4 
         samba-python.x86_64 0:4.6.2-11.el7_4 samba-winbind.x86_64 0:4.6.2-11.el7_4 samba-winbind-modules.x86_64 0:4.6.2-11.el7_4 
        
        Complete!
        [root@cb1ividmn01 ~]#
        
        >>> Run AD Pkg Setup
        [root@cb1ividmn01 ~]# kinit admin
        Password for admin@LE.DP.NIX.PCF.LOCAL: 
        
        [root@cb1ividmn01 ~]# klist
        Ticket cache: KEYRING:persistent:0:0
        Default principal: admin@LE.DP.NIX.PCF.LOCAL
        
        Valid starting Expires Service principal
        23/11/17 17:22:34 24/11/17 17:22:31 krbtgt/LE.DP.NIX.PCF.LOCAL@LE.DP.NIX.PCF.LOCAL
        [root@cb1ividmn01 ~]# ipa-adtrust-install 
        
        The log file for this installation can be found in /var/log/ipaserver-install.log
        ===================================================================
        This program will setup components needed to establish trust to AD domains for
        the IPA Server.
        
        This includes:
         * Configure Samba
         * Add trust related objects to IPA LDAP server
        
        To accept the default shown in brackets, press the Enter key.
        
        Configuring cross-realm trusts for IPA server requires password for user 'admin'.
        This user is a regular system account used for IPA server administration.
        
        admin password: 
        
        WARNING: The smb.conf already exists. Running ipa-adtrust-install will break your existing samba configuration.
        
        
        Do you wish to continue? [no]: yes
        Do you want to enable support for trusted domains in Schema Compatibility plugin?
        This will allow clients older than SSSD 1.9 and non-Linux clients to work with trusted users.
        
        Enable trusted domains support in slapi-nis? [no]: yes
        
        Enter the NetBIOS name for the IPA domain.
        Only up to 15 uppercase ASCII letters, digits and dashes are allowed.
        Example: EXAMPLE.
        
        
        NetBIOS domain name [LE]: NIX
        
        
        WARNING: 5 existing users or groups do not have a SID identifier assigned.
        Installer can run a task to have ipa-sidgen Directory Server plugin generate
        the SID identifier for all these users. Please note, the in case of a high
        number of users and groups, the operation might lead to high replication
        traffic and performance degradation. Refer to ipa-adtrust-install(1) man page
        for details.
        
        Do you want to run the ipa-sidgen task? [no]: yes
        
        The following operations may take some minutes to complete.
        Please wait until the prompt is returned.
        
        Configuring CIFS
         [1/24]: validate server hostname
         [2/24]: stopping smbd
         [3/24]: creating samba domain object
         [4/24]: creating samba config registry
         [5/24]: writing samba config file
         [6/24]: adding cifs Kerberos principal
         [7/24]: adding cifs and host Kerberos principals to the adtrust agents group
         [8/24]: check for cifs services defined on other replicas
         [9/24]: adding cifs principal to S4U2Proxy targets
         [10/24]: adding admin(group) SIDs
         [11/24]: adding RID bases
         [12/24]: updating Kerberos config
        'dns_lookup_kdc' already set to 'true', nothing to do.
         [13/24]: activating CLDAP plugin
         [14/24]: activating sidgen task
         [15/24]: configuring smbd to start on boot
         [16/24]: adding special DNS service records
         [17/24]: enabling trusted domains support for older clients via Schema Compatibility plugin
         [18/24]: restarting Directory Server to take MS PAC and LDAP plugins changes into account
         [19/24]: adding fallback group
         [20/24]: adding Default Trust View
         [21/24]: setting SELinux booleans
         [22/24]: starting CIFS services
         [23/24]: adding SIDs to existing users and groups
        This step may take considerable amount of time, please wait..
         [24/24]: restarting smbd
        Done configuring CIFS.
        
        ===================================================================
        Setup complete
        
        You must make sure these network ports are open:
        	TCP Ports:
        	 * 135: epmap
        	 * 138: netbios-dgm
        	 * 139: netbios-ssn
        	 * 445: microsoft-ds
        	 * 1024..1300: epmap listener range
        	 * 3268: msft-gc
        	UDP Ports:
        	 * 138: netbios-dgm
        	 * 139: netbios-ssn
        	 * 389: (C)LDAP
        	 * 445: microsoft-ds
        
        See the ipa-adtrust-install(1) man page for more details
        
        ===================================================================
        [root@cb1ividmn01 ~]#
        
        >>> Test local Samba
        Installed:
         samba-client.x86_64 0:4.6.2-11.el7_4 
        
        Dependency Installed:
         libarchive.x86_64 0:3.1.2-10.el7_2 
        
        Complete!
        [root@cb1ividmn01 ~]#
        
        [root@cb1ividmn01 ~]# smbclient -L $HOSTNAME -k
        lp_load_ex: changing to config backend registry
        OS=[Windows 6.1] Server=[Samba 4.6.2]
        
        	Sharename Type Comment
        	--------- ---- -------
        	IPC$ IPC IPC Service (Samba 4.6.2)
        OS=[Windows 6.1] Server=[Samba 4.6.2]
        
        	Server Comment
        	--------- -------
        
        	Workgroup Master
        	--------- -------
        [root@cb1ividmn01 ~]#

    DNS - Post AD Pkgs

        [root@cb1ividmn01 ~]# ./dns-idm.sh 
        Searching: cb1ividmn01 A Records 
        cb1ividmn01.le.dp.nix.pcf.local. 1200 IN A 10.69.120.5
        
        Searching: cb1ividmn02 A Records 
        cb1ividmn02.le.dp.nix.pcf.local. 1200 IN A 10.69.120.6
        
        Searching: ipa-ca Records 
        ipa-ca.le.dp.nix.pcf.local. 86400 IN A 10.69.120.6 ipa-ca.le.dp.nix.pcf.local. 86400 IN A 10.69.120.5
        
        Searching: TXT; 
        _kerberos.le.dp.nix.pcf.local. 86400 IN	TXT	"LE.DP.NIX.PCF.LOCAL"
        
        Searching: _ldap._tcp; 
        _ldap._tcp.le.dp.nix.pcf.local.	86400 IN SRV	0 100 389 cb1ividmn02.le.dp.nix.pcf.local.
        _ldap._tcp.le.dp.nix.pcf.local.	86400 IN SRV	0 100 389 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _kerberos._tcp
        _kerberos._tcp.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        _kerberos._tcp.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        
        Searching: _kerberos._udp
        _kerberos._udp.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        _kerberos._udp.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        
        Searching: _kerberos-master._tcp
        _kerberos-master._tcp.le.dp.nix.pcf.local. 86400 IN SRV	0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        _kerberos-master._tcp.le.dp.nix.pcf.local. 86400 IN SRV	0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        
        Searching: _kerberos-master._udp
        _kerberos-master._udp.le.dp.nix.pcf.local. 86400 IN SRV	0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        _kerberos-master._udp.le.dp.nix.pcf.local. 86400 IN SRV	0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _ntp._udp
        _ntp._udp.le.dp.nix.pcf.local. 86400 IN	SRV	0 100 123 cb1ividmn02.le.dp.nix.pcf.local.
        _ntp._udp.le.dp.nix.pcf.local. 86400 IN	SRV	0 100 123 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs
        _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.le.dp.nix.pcf.local. 86400 IN SRV 0 100 389 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _kerberos._udp.Default-First-Site-Name._sites.dc._msdcs
        _kerberos._udp.Default-First-Site-Name._sites.dc._msdcs.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _kerberos._tcp.dc._msdcs
        _kerberos._tcp.dc._msdcs.le.dp.nix.pcf.local. 86400 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _ldap._tcp.dc._msdcs
        _ldap._tcp.dc._msdcs.le.dp.nix.pcf.local. 86400	IN SRV 0 100 389 cb1ividmn01.le.dp.nix.pcf.local.
        
        >>> Query IdM Records via AD DNS
        
        [root@cb1ividmn01 ~]# ./dns-2ad.sh 
        Using Nameserver: 	10.69.120.2
        Searching: cb1ividmn01 A Records 
        cb1ividmn01.le.dp.nix.pcf.local. 804 IN A 10.69.120.5
        
        Searching: cb1ividmn02 A Records 
        cb1ividmn02.le.dp.nix.pcf.local. 804 IN A 10.69.120.6
        
        Searching: ipa-ca Records 
        ipa-ca.le.dp.nix.pcf.local. 86004 IN A 10.69.120.5 ipa-ca.le.dp.nix.pcf.local. 86004 IN A 10.69.120.6
        
        Searching: TXT; 
        _kerberos.le.dp.nix.pcf.local. 86004 IN	TXT	"LE.DP.NIX.PCF.LOCAL"
        
        Searching: _ldap._tcp; 
        _ldap._tcp.le.dp.nix.pcf.local.	86004 IN SRV	0 100 389 cb1ividmn01.le.dp.nix.pcf.local.
        _ldap._tcp.le.dp.nix.pcf.local.	86004 IN SRV	0 100 389 cb1ividmn02.le.dp.nix.pcf.local.
        
        Searching: _kerberos._tcp
        _kerberos._tcp.le.dp.nix.pcf.local. 86004 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        _kerberos._tcp.le.dp.nix.pcf.local. 86004 IN SRV 0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        
        Searching: _kerberos._udp
        _kerberos._udp.le.dp.nix.pcf.local. 86004 IN SRV 0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        _kerberos._udp.le.dp.nix.pcf.local. 86004 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _kerberos-master._tcp
        _kerberos-master._tcp.le.dp.nix.pcf.local. 86004 IN SRV	0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        _kerberos-master._tcp.le.dp.nix.pcf.local. 86004 IN SRV	0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        
        Searching: _kerberos-master._udp
        _kerberos-master._udp.le.dp.nix.pcf.local. 86004 IN SRV	0 100 88 cb1ividmn02.le.dp.nix.pcf.local.
        _kerberos-master._udp.le.dp.nix.pcf.local. 86004 IN SRV	0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _ntp._udp
        _ntp._udp.le.dp.nix.pcf.local. 86004 IN	SRV	0 100 123 cb1ividmn02.le.dp.nix.pcf.local.
        _ntp._udp.le.dp.nix.pcf.local. 86004 IN	SRV	0 100 123 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs
        _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.le.dp.nix.pcf.local. 86004 IN SRV 0 100 389 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _kerberos._udp.Default-First-Site-Name._sites.dc._msdcs
        _kerberos._udp.Default-First-Site-Name._sites.dc._msdcs.le.dp.nix.pcf.local. 86004 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _kerberos._tcp.dc._msdcs
        _kerberos._tcp.dc._msdcs.le.dp.nix.pcf.local. 86004 IN SRV 0 100 88 cb1ividmn01.le.dp.nix.pcf.local.
        
        Searching: _ldap._tcp.dc._msdcs
        _ldap._tcp.dc._msdcs.le.dp.nix.pcf.local. 86004	IN SRV 0 100 389 cb1ividmn01.le.dp.nix.pcf.local.
        
        [root@cb1ividmn01 ~]#

    Creating AD Trust

        [root@cb1ividmn01 ~]# kinit admin
        Password for admin@LE.DP.NIX.PCF.LOCAL:
        
        [root@cb1ividmn01 ~]# klist
        Ticket cache: KEYRING:persistent:0:0
        Default principal: admin@LE.DP.NIX.PCF.LOCAL
         
        Valid starting Expires Service principal
        11/24/2017 13:04:14 11/25/2017 13:04:05 krbtgt/LE.DP.NIX.PCF.LOCAL@LE.DP.NIX.PCF.LOCAL
        
        
        [root@cb1ividmn01 ~]# ipa trust-add --type=ad pcf.local --admin scajkelly --password
        Active Directory domain administrator's password:
        --------------------------------------------------
        Added Active Directory trust for realm "pcf.local"
        --------------------------------------------------
         Realm name: pcf.local
         Domain NetBIOS name: PCF
         Domain Security Identifier: S-1-5-21-1430749430-579667954-1438867981
         Trust direction: Trusting forest
         Trust type: Active Directory domain
         Trust status: Established and verified
        [root@cb1ividmn01 ~]#
        
        [root@cb1ividmn01 ~]# ipa trust-show
        Realm name: PCF.LOCAL
         Realm name: pcf.local
         Domain NetBIOS name: PCF
         Domain Security Identifier: S-1-5-21-1430749430-579667954-1438867981
         Trust direction: Trusting forest
         Trust type: Active Directory domain
        [root@cb1ividmn01 ~]
        
        >>>> Validate Lookup
        
        [root@cb1ividmn01 ~]# id 'scajkelly@pcf.local'
        uid=1336201119(scajkelly@pcf.local) gid=1336201119(scajkelly@pcf.local) groups=1336201119(scajkelly@pcf.local),1336200519(enterprise admins@pcf.local),1336200518(schema admins@pcf.local),1336200512(domain admins@pcf.local),1336200513(domain users@pcf.local)
        [root@cb1ividmn01 ~]#
        
        >>> AD User Login Test
        
        [root@cb1ividmn01 ~]# ssh 'pcf.local\capAKHIMJI@localhost'
        Password: 
        Creating home directory for pcf.local\capAKHIMJI.
        -sh-4.2$
        
        -sh-4.2$ whoami
        capakhimji@pcf.local
        
        -sh-4.2$ id
        uid=1336201148(capakhimji@pcf.local) gid=1336201148(capakhimji@pcf.local) groups=1336201148(capakhimji@pcf.local),1336200513(domain users@pcf.local) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
        
        -sh-4.2$ klist
        Ticket cache: KEYRING:persistent:1336201148:krb_ccache_vD5elgQ
        Default principal: capAKHIMJI@PCF.LOCAL
        
        Valid starting Expires Service principal
        24/11/17 13:31:39 24/11/17 23:31:39 krbtgt/PCF.LOCAL@PCF.LOCAL
        	renew until 25/11/17 13:31:39
        -sh-4.2$

    Windows DC - Trust Validation

    ![](https://static.notion-static.com/8661810c1d0641c99d948448fe4257b1/Untitled)

    Extend Trust to Secondary Node

        >>> Install Pkgs
        
        Installed:
         ipa-server-trust-ad.x86_64 0:4.5.0-21.el7_4.2.2 
        
        Dependency Installed:
         pyldb.x86_64 0:1.1.29-1.el7 pytalloc.x86_64 0:2.1.9-1.el7 python-libsss_nss_idmap.x86_64 0:1.15.2-50.el7_4.6 python-sss.x86_64 0:1.15.2-50.el7_4.6 python-tdb.x86_64 0:1.3.12-2.el7 
         python-tevent.x86_64 0:0.9.31-1.el7 samba.x86_64 0:4.6.2-11.el7_4 samba-common-libs.x86_64 0:4.6.2-11.el7_4 samba-common-tools.x86_64 0:4.6.2-11.el7_4 samba-libs.x86_64 0:4.6.2-11.el7_4 
         samba-python.x86_64 0:4.6.2-11.el7_4 samba-winbind.x86_64 0:4.6.2-11.el7_4 samba-winbind-modules.x86_64 0:4.6.2-11.el7_4 
        
        Complete!
        [root@cb1ividmn02 ~]#
        
        >>> Enable Trust
        
        [root@cb1ividmn02 ~]# kinit admin
        Password for admin@LE.DP.NIX.PCF.LOCAL: 
        
        [root@cb1ividmn02 ~]# klist
        Ticket cache: KEYRING:persistent:0:0
        Defult principal: admin@LE.DP.NIX.PCF.LOCAL
        
        Valid starting Expires Service principal
        24/11/17 13:43:48 25/11/17 13:43:44 krbtgt/LE.DP.NIX.PCF.LOCAL@LE.DP.NIX.PCF.LOCAL
        [root@cb1ividmn02 ~]#
        
        [root@cb1ividmn02 ~]# ipa-adtrust-install 
        
        The log file for this installation can be found in /var/log/ipaserver-install.log
        ===================================================================
        This program will setup components needed to establish trust to AD domains for
        the IPA Server.
        
        This includes:
         * Configure Samba
         * Add trust related objects to IPA LDAP server
        
        To accept the default shown in brackets, press the Enter key.
        
        Configuring cross-realm trusts for IPA server requires password for user 'admin'.
        This user is a regular system account used for IPA server administration.
        
        admin password: 
        
        WARNING: The smb.conf already exists. Running ipa-adtrust-install will break your existing samba configuration.
        
        
        Do you wish to continue? [no]: yes
        Do you want to enable support for trusted domains in Schema Compatibility plugin?
        This will allow clients older than SSSD 1.9 and non-Linux clients to work with trusted users.
        
        Enable trusted domains support in slapi-nis? [no]: yes
        
        
        The following operations may take some minutes to complete.
        Please wait until the prompt is returned.
        
        Configuring CIFS
         [1/23]: validate server hostname
         [2/23]: stopping smbd
         [3/23]: creating samba domain object
        Samba domain object already exists
         [4/23]: creating samba config registry
         [5/23]: writing samba config file
         [6/23]: adding cifs Kerberos principal
         [7/23]: adding cifs and host Kerberos principals to the adtrust agents group
         [8/23]: check for cifs services defined on other replicas
         [9/23]: adding cifs principal to S4U2Proxy targets
         [10/23]: adding admin(group) SIDs
        Admin SID already set, nothing to do
        Admin group SID already set, nothing to do
         [11/23]: adding RID bases
        RID bases already set, nothing to do
         [12/23]: updating Kerberos config
        'dns_lookup_kdc' already set to 'true', nothing to do.
         [13/23]: activating CLDAP plugin
         [14/23]: activating sidgen task
         [15/23]: configuring smbd to start on boot
         [16/23]: adding special DNS service records
         [17/23]: enabling trusted domains support for older clients via Schema Compatibility plugin
         [18/23]: restarting Directory Server to take MS PAC and LDAP plugins changes into account
         [19/23]: adding fallback group
        Fallback group already set, nothing to do
         [20/23]: adding Default Trust View
        Default Trust View already exists.
         [21/23]: setting SELinux booleans
         [22/23]: starting CIFS services
         [23/23]: restarting smbd
        Done configuring CIFS.
        
        ===================================================================
        Setup complete
        
        You must make sure these network ports are open:
        	TCP Ports:
        	 * 135: epmap
        	 * 138: netbios-dgm
        	 * 139: netbios-ssn
        	 * 445: microsoft-ds
        	 * 1024..1300: epmap listener range
        	 * 3268: msft-gc
        	UDP Ports:
        	 * 138: netbios-dgm
        	 * 139: netbios-ssn
        	 * 389: (C)LDAP
        	 * 445: microsoft-ds
        
        See the ipa-adtrust-install(1) man page for more details
        
        ===================================================================
        
        [root@cb1ividmn02 ~]#
        
        >>> Validate Login
        
        [root@cb1ividmn02 ~]# ssh 'pcf.local\capAKHIMJI'@localhost
        Password: 
        Could not chdir to home directory /home/pcf.local/capakhimji: No such file or directory
        
        -sh-4.2$ whoami
        capakhimji@pcf.local
        
        -sh-4.2$ id
        uid=1336201148(capakhimji@pcf.local) gid=1336201148(capakhimji@pcf.local) groups=1336201148(capakhimji@pcf.local),1336200513(domain users@pcf.local) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
        
        -sh-4.2$ klist
        Ticket cache: KEYRING:persistent:1336201148:krb_ccache_Zl9wR5t
        Default principal: capAKHIMJI@PCF.LOCAL
        
        Valid starting Expires Service principal
        24/11/17 13:46:55 24/11/17 23:46:55 krbtgt/PCF.LOCAL@PCF.LOCAL
        	renew until 25/11/17 13:46:55
        -sh-4.2$

    Join RHEL7 Clients - LIST

        #ANSIBLE
        
        10.69.65.2	 [cb1ivansn01.le.dp.pcf.local](http://cb1ivansn01.le.dp.pcf.local) [DONE]
        
        
        #MASTERS
        
        10.69.64.50	cb1avocpmn01.le.dp.pcf.local
        10.69.64.51	cb1avocpmn02.le.dp.pcf.local
        10.69.64.52	cb1avocpmn03.le.dp.pcf.local
        
        #Infrastructure Nodes
        
        10.69.64.53	cb1avocpin01.le.dp.pcf.local
        10.69.64.54	cb1avocpin02.le.dp.pcf.local
        10.69.64.55	cb1avocpin03.le.dp.pcf.local
        10.69.64.56	cb1avocpin04.le.dp.pcf.local
        10.69.64.57	cb1avocpin05.le.dp.pcf.local
        10.69.64.58	cb1avocpin06.le.dp.pcf.local
        
        
        #Application Nodes
        
        10.69.64.59	cb1avocpan01.le.dp.pcf.local
        10.69.64.60	cb1avocpan02.le.dp.pcf.local
        10.69.64.61	cb1avocpan03.le.dp.pcf.local
        10.69.64.62	cb1avocpan04.le.dp.pcf.local

    Client Joining Process

        [root@cb1ivansn01 ~]# yum install ipa-client
        ...
        Installed:
         ipa-client.x86_64 0:4.5.0-21.el7_4.2.2
        
        [root@cb1ivansn01 ~]# cat /etc/resolv.conf 
        # Generated by NetworkManager
        search le.dp.pcf.local le.dp.nix.pcf.local
        nameserver 10.69.120.2
        nameserver 10.69.120.3
        nameserver 10.69.120.4
        
        [root@cb1ivansn01 ~]# ipa-client-install --domain=le.dp.nix.pcf.local --mkhomedir --hostname=cb1ivansn01.le.dp.pcf.local
        WARNING: ntpd time&date synchronization service will not be configured as
        conflicting service (chronyd) is enabled
        Use --force-ntpd option to disable it and force configuration of ntpd
        
        Discovery was successful!
        Client hostname: cb1ivansn01.le.dp.pcf.local
        Realm: LE.DP.NIX.PCF.LOCAL
        DNS Domain: le.dp.nix.pcf.local
        IPA Server: cb1ividmn02.le.dp.nix.pcf.local
        BaseDN: dc=le,dc=dp,dc=nix,dc=pcf,dc=local
        
        Continue to configure the system with these values? [no]: yes
        User authorized to enroll computers: admin
        Password for admin@LE.DP.NIX.PCF.LOCAL: 
        Successfully retrieved CA cert
         Subject: CN=NPRODROOTCA1
         Issuer: CN=NPRODROOTCA1
         Valid From: 2017-11-16 22:26:42
         Valid Until: 2027-11-16 22:36:42
        
         Subject: CN=Certificate Authority,O=LE.DP.NIX.PCF.LOCAL
         Issuer: CN=NPRODROOTCA1
         Valid From: 2017-11-20 14:59:26
         Valid Until: 2023-11-20 15:09:26
        
        Enrolled in IPA realm LE.DP.NIX.PCF.LOCAL
        Created /etc/ipa/default.conf
        New SSSD config will be created
        Configured sudoers in /etc/nsswitch.conf
        Configured /etc/sssd/sssd.conf
        Configured /etc/krb5.conf for IPA realm LE.DP.NIX.PCF.LOCAL
        trying https://cb1ividmn02.le.dp.nix.pcf.local/ipa/json
        [try 1]: Forwarding 'schema' to json server 'https://cb1ividmn02.le.dp.nix.pcf.local/ipa/json'
        trying https://cb1ividmn02.le.dp.nix.pcf.local/ipa/session/json
        [try 1]: Forwarding 'ping' to json server 'https://cb1ividmn02.le.dp.nix.pcf.local/ipa/session/json'
        [try 1]: Forwarding 'ca_is_enabled' to json server 'https://cb1ividmn02.le.dp.nix.pcf.local/ipa/session/json'
        Systemwide CA database updated.
        Adding SSH public key from /etc/ssh/ssh_host_rsa_key.pub
        Adding SSH public key from /etc/ssh/ssh_host_ecdsa_key.pub
        Adding SSH public key from /etc/ssh/ssh_host_ed25519_key.pub
        [try 1]: Forwarding 'host_mod' to json server 'https://cb1ividmn02.le.dp.nix.pcf.local/ipa/session/json'
        Could not update DNS SSHFP records.
        SSSD enabled
        Configured /etc/openldap/ldap.conf
        Configured /etc/ssh/ssh_config
        Configured /etc/ssh/sshd_config
        Configuring le.dp.nix.pcf.local as NIS domain.
        Client configuration complete.
        The ipa-client-install command was successful
        [root@cb1ivansn01 ~]#
        
        ### Validate Lookup and KDC
        
        >> IdM User
        [root@cb1ivansn01 ~]# id admin
        uid=1856200000(admin) gid=1856200000(admins) groups=1856200000(admins)
        [root@cb1ivansn01 ~]#
        
        [root@cb1ivansn01 ~]# kinit admin
        Password for admin@LE.DP.NIX.PCF.LOCAL: 
        
        [root@cb1ivansn01 ~]# klist
        Ticket cache: KEYRING:persistent:0:0
        Default principal: admin@LE.DP.NIX.PCF.LOCAL
        
        Valid starting Expires Service principal
        29/11/17 10:44:59 30/11/17 10:44:57 krbtgt/LE.DP.NIX.PCF.LOCAL@LE.DP.NIX.PCF.LOCAL
        [root@cb1ivansn01 ~]#
        
        >> AD User
        [root@cb1ivansn01 ~]# id capakhimji@PCF.LOCAL
        uid=1336201148(capakhimji@pcf.local) gid=1336201148(capakhimji@pcf.local) groups=1336201148(capakhimji@pcf.local),1336200513(domain users@pcf.local)
        [root@cb1ivansn01 ~]#
        
        [root@cb1ivansn01 ~]# kinit capakhimji@PCF.LOCAL
        Password for capakhimji@PCF.LOCAL: 
        
        [root@cb1ivansn01 ~]# klist
        Ticket cache: KEYRING:persistent:0:0
        Default principal: capAKHIMJI@PCF.LOCAL
        
        Valid starting Expires Service principal
        29/11/17 10:45:50 29/11/17 20:45:50 krbtgt/PCF.LOCAL@PCF.LOCAL
        	renew until 30/11/17 10:45:42
        
        >>> AD User Login via IdM
        $ ssh 'capakhimji@PCF.LOCAL'@10.69.65.2
        Password: 
        
        Creating home directory for capakhimji@PCF.LOCAL.
        
        -sh-4.2$ whoami
        capakhimji@pcf.local
        
        -sh-4.2$ id
        uid=1336201148(capakhimji@pcf.local) gid=1336201148(capakhimji@pcf.local) groups=1336201148(capakhimji@pcf.local),1336200513(domain users@pcf.local)
        
        -sh-4.2$ klist
        Ticket cache: KEYRING:persistent:1336201148:krb_ccache_fxVExmS
        Default principal: capAKHIMJI@PCF.LOCAL
        
        Valid starting Expires Service principal
        29/11/17 10:47:16 29/11/17 20:47:16 krbtgt/PCF.LOCAL@PCF.LOCAL
        	renew until 30/11/17 10:47:16
        -sh-4.2$

  - Microsoft DC Info

        CB1IVDCN01.pcf.local 10.69.120.2
        CB1IVDCN02.pcf.local 10.69.120.3
        CB1IVDCN03.pcf.local 10.69.120.4

- OCP Active Directory - Set-up Instructions

  Block to add to master-conf.yaml (add to add 3 and restart services)

      #### AD/LDAP Integration #### 
      RUN PLAYBOOK FROM ANSIBLE HOST
      
      - Create the AD/LDAP configuration stanza on each master and restart services
      
      cat <<EOF > ldap.yaml
      ---
      - hosts: masters
       tasks:
       - name: Remove htpasswd provider on masters and restart
       replace:
       path: /etc/origin/master/master-config.yaml
       regexp: '(?s)(?<= identityProviders:\n).*?(?= masterCA)'
       replace: ''
       backup: yes
       - name: Add AD configuration to masters and restart
       blockinfile:
       dest: /etc/origin/master/master-config.yaml
       marker: "# {mark} ANSIBLE MANAGED ACTIVE DIRECTORY BLOCK #"
       insertafter: ' identityProviders:'
       block: |2
       - name: "Active Directory - PCBANK"
       challenge: true
       login: true
       mappingMethod: add
       provider:
       apiVersion: v1
       kind: LDAPPasswordIdentityProvider
       attributes:
       id:
       - sAMAccountName
       - cn
       bindDN: "CN=svcOCPConnect,OU=pcfServiceAccounts,DC=pcf,DC=local"
       bindPassword: "Pc!dm1nOCP@$99"
       insecure: true
       url: "ldap://pcf.local:389/DC=pcf,DC=local?sAMAccountName?sub?(memberOf=CN=sgOCPAdmin,OU=pcfSecurityGroups,DC=pcf,DC=local)"
       backup: yes
       state: present
       - name: restart controller service
       service:
       name: atomic-openshift-master-controllers
       state: restarted
       - name: restart api service
       service:
       name: atomic-openshift-master-api
       state: restarted
      EOF
      
      
      - Create the following AD/LDAP synchronization file
      RUN SCRIPT FROM MASTER HOST
      
      cat << EOF > ldap-sync-config.yaml
      kind: LDAPSyncConfig
      apiVersion: v1
      groupUIDNameMapping:
       "CN=sgOCPAdmin,OU=pcfSecurityGroups,DC=pcf,DC=local": openshift_admins
       "CN=sgOCPUsers,OU=pcfSecurityGroups,DC=pcf,DC=local": openshift_users
      url: ldap://pcf.local:389
      bindDN: "CN=svcOCPConnect,OU=pcfServiceAccounts,DC=pcf,DC=local"
      bindPassword: "Pc!dm1nOCP@$99"
      insecure: true
      rfc2307:
       groupsQuery:
       baseDN: "OU=pcfSecurityGroups,DC=pcf,DC=local"
       scope: sub
       derefAliases: never
       pageSize: 10000
       filter: (objectClass=*)
       groupUIDAttribute: dn
       groupNameAttributes: [ cn ]
       groupMembershipAttributes: [ member ]
       usersQuery:
       baseDN: "CN=sgOCPUsers,OU=pcfSecurityGroups,DC=pcf,DC=local"
       scope: sub
       derefAliases: never
       pageSize: 10000
       userUIDAttribute: dn
       userNameAttributes: [ sAMAccountName ]
       tolerateMemberNotFoundErrors: false
       tolerateMemberOutOfScopeErrors: false
      EOF
      
      
      THIS WILL BE USED TO CREATE NEW GROUPS AND USERS
      
      - Create the AD/LDAP whitelist
      cat << EOF > ldap_whitelist
      CN=sgOCPAdmin,OU=pcfSecurityGroups,DC=pcf,DC=local
      CN=sgOCPUsers,OU=pcfSecurityGroups,DC=pcf,DC=local
      EOF
      
      
      
      - Run a synchronization job
      RUN SCRIPT FROM MASTER HOST
      
      THIS WILL BE USED TO CREATE NEW GROUPS AND USERS
      
      root@cb1avocpmn01 ~]# oadm groups sync --sync-config=/root/ldap-sync-config.yaml --whitelist=/root/ldap_whitelist --confirm
      group/openshift_admins
      group/openshift_users
      [root@cb1avocpmn01 ~]#
      
      
      ***NEEDS TO BE DONE ON EACH MASTER
      
      #### Run AD/LDAP Synchronization as a Cron Job
      - Create the AD/LDAP sync shell script and make executable
       
      mkdir /home/ocpadmin/scripts
      cat <<EOF > /home/ocpadmin/scripts/ldap_sync.sh
      #!/bin/bash
      /bin/oc login -u system:admin
      /bin/oadm groups sync --sync-config=/home/ocpadmin/ansible_install/ldap-sync-config.yaml --whitelist=/home/ocpadmin/ansible_install/ldap_whitelist --confirm
      EOF
      
      chmod +x /home/ocpadmin/scripts/ldap_sync.sh
      
       - Add to crontab of the root user on masters nodes with offset schedules
      
      sudo crontab -e
      0,30 * * * * /home/ocpadmin/scripts/ldap_sync.sh 2>&1
      15,45 * * * * /home/ocpadmin/scripts/ldap_sync.sh 2>&1
      
      
      #### AD Group Permissions
      
      RUN FROM 1 MASTER
      
      oadm policy add-cluster-role-to-group cluster-admin openshift_admins
      
      oadm policy remove-cluster-role-from-group self-provisioner system:authenticated system:authenticated:oauth
      
      oadm policy add-cluster-role-to-group self-provisioner openshift_users
      
      [root@cb1avocpmn01 ~]# oadm policy add-cluster-role-to-group admin openshift_admins
      cluster role "admin" added: "openshift_admins"
      
      [root@cb1avocpmn01 ~]# oadm policy add-cluster-role-to-group cluster-admin openshift_admins
      cluster role "cluster-admin" added: "openshift_admins"
      
      [root@cb1avocpmn01 ~]# oadm policy remove-cluster-role-from-group self-provisioner system:authenticated system:authenticated:oauth
      cluster role "self-provisioner" removed: ["system:authenticated" "system:authenticated:oauth"]
      
      [root@cb1avocpmn01 ~]# oadm policy add-cluster-role-to-group self-provisioner openshift_users
      cluster role "self-provisioner" added: "openshift_users"
      [root@cb1avocpmn01 ~]#

- OCP Persistent Volumes

      >> logging-pv.yaml
      apiVersion: v1
      kind: PersistentVolume
      metadata:
       name: logging-pv
      spec:
       capacity:
       storage: 200Gi
       accessModes:
       - ReadWriteOnce
       iscsi:
       targetPortal: 192.168.211.10:3260
       portals: ['192.168.211.10:3260', '192.168.211.10:3260']
       iqn: iqn.1992-08.com.netapp:sn.da1eb7e9affb11e7b56d00a098b7d772:vs.3
       lun: 0
       fsType: 'ext4'
       readOnly: false
      
      >>loggin-pvc.yml
       apiVersion: v1
       kind: PersistentVolumeClaim
       metadata:
       name: elasticsearch-storage-pvc
       spec:
       accessModes:
       - ReadWriteOnce
       resources:
       requests:
       storage: 200Gi
      
      oc create -f logging-pvc.yml
      oc volume dc/logging-es-data-master-ibznloku --add --name=elasticsearch-storage -t pvc --claim-name=elasticsearch-storage-pvc --overwrite
      
      -----------------------------------------------------------------------
      >> metrics-pv.yml
      apiVersion: v1
      kind: PersistentVolume
      metadata:
       name: metrics-pv
      spec:
       capacity:
       storage: 200Gi
       accessModes:
       - ReadWriteOnce
       iscsi:
       targetPortal: 192.168.211.10:3260
       portals: ['192.168.211.10:3260', '192.168.211.10:3260']
       iqn: iqn.1992-08.com.netapp:sn.da1eb7e9affb11e7b56d00a098b7d772:vs.3
       lun: 1
       fsType: 'ext4'
       readOnly: false
      
      >> metrics-pvc.yml
       apiVersion: v1
       kind: PersistentVolumeClaim
       metadata:
       name: cassandra-metrics-pvc
       spec:
       accessModes:
       - ReadWriteOnce
       resources:
       requests:
       storage: 200Gi
      
      oc create -f metrics-pvc.yml
      oc volume rc/hawkular-cassandra-1 --add --name=cassandra-data -t pvc --claim-name=cassandra-metrics-pvc --overwrite
      
      -----------------------------------------------------------------------
      >> registry-pv.yml
      apiVersion: v1
      kind: PersistentVolume
      metadata:
       name: registry-pv
      spec:
       capacity:
       storage: 200Gi
       accessModes:
       - ReadWriteOnce
       iscsi:
       targetPortal: 192.168.211.10:3260
       portals: ['192.168.211.10:3260', '192.168.211.10:3260']
       iqn: iqn.1992-08.com.netapp:sn.da1eb7e9affb11e7b56d00a098b7d772:vs.3
       lun: 2
       fsType: 'ext4'
       readOnly: false
      
      >> registry-pvc.yml
       apiVersion: v1
       kind: PersistentVolumeClaim
       metadata:
       name: registry-storage-pvc
       spec:
       accessModes:
       - ReadWriteOnce
       resources:
       requests:
       storage: 200Gi
      
      oc create -f registry-pvc.yml
      oc volume dc/docker-registry --add --name=registry-storage -t pvc --claim-name=registry-storage-pvc --overwrite
      
      -----------------------------------------------------------------------

- Logging Fix's - Big address with proper URL

   [https://kubernetes.default.svc.cluster.local:443](https://kubernetes.default.svc.cluster.local:443) 

- OpenShift SDN Details Explained

   **openshift_master_portal_net** 

  This variable configures the subnet in which services will be created within the OpenShift Container Platform SDN. This network block should be private and must not conflict with any existing network blocks in your infrastructure to which pods, nodes, or the master may require access to, or the installation will fail. **Defaults to 172.30.0.0/16** , and cannot be re-configured after deployment. If changing from the default, **avoid 172.17.0.0/16** , which the docker0 network bridge uses by default, or modify the docker0 network.

   **osm_host_subnet_length** 

  This variable specifies the size of the per host subnet allocated for pod IPs by OpenShift Container Platform SDN. Defaults to 9 which means that a subnet of size /23 is allocated to each host; for example, given the **default 10.128.0.0/14** cluster network, this will allocate **10.128.0.0/23, 10.128.2.0/23, 10.128.4.0/23** , and so on. This cannot be re-configured after deployment.

   **osm_cluster_network_cidr** 

  This variable overrides the SDN cluster network CIDR block. This is the network from which pod IPs are assigned. This network block should be a private block and must not conflict with existing network blocks in your infrastructure to which pods, nodes, or the master may require access. **Defaults to 10.128.0.0/14** and cannot be arbitrarily re-configured after deployment, although certain changes to it can be made in the SDN master configuration.

  ---

- Open Items that we discussed in Architecture but not addresses

  SSL Certificate Setup - Cert's have still not been provided

  Load Balancing - Need final F5's setup and DNS changes made and tested

  PV setup - We have PV's form infrastructure PODs but none ready for apps

  Satellite - Satellite base install was done but never configured - Using RNN

  Satellite OpenSCAP - This was discussed an may want ot be configured in furute

  Container Security Model? - Future work in this Area reccomended

  Container Monitoring - Future work in this Area reccomended

  Cloudforms virtual appliance was never deployed and configured 

  3rd party logging configureation to LogRythm - Was not available or configured

  Performance testing and tuning / validation

  Proactive environment tuning, log rotation, docker vg clean-up

  May want to consider a 3.7 upgrade