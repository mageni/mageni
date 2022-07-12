###############################################################################
# OpenVAS Vulnerability Test
#
# Determine OS and list of installed packages via SSH login
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
# Tim Brown <timb@openvas.org>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc. http://www.securityspace.com
# Copyright (C) 2008 Tim Brown
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.50282");
  script_version("2019-05-17T11:50:38+0000");
  script_tag(name:"last_modification", value:"2019-05-17 11:50:38 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2008-01-17 22:05:49 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Determine OS and list of installed packages via SSH login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc. http://www.securityspace.com & Tim Brown");
  script_family("General");
  script_dependencies("ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success");

  script_tag(name:"summary", value:"This script will, if given a userid/password or
  key to the remote system, login to that system, determine the OS it is running, and for
  supported systems, extract the list of installed packages/rpms.");

  script_tag(name:"insight", value:"The ssh protocol is used to log in. If a specific port is
  configured for the credential, then only this port will be tried. Else any port that offers
  ssh, usually port 22.

  Upon successful login, the command 'uname -a' is issued to find out about the type and version
  of the operating system.

  The result is analysed for various patterns and in several cases additional commands are tried
  to find out more details and to confirm a detection.

  The regular Linux distributions are detected this way as well as other unixoid systems and
  also many Linux-based devices and appliances.

  If the system offers a package database, for example RPM- or DEB-based, this full list of
  installed packages is retrieved for further patch-level checks.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

cmdline = 0;
SCRIPT_DESC = "Determine OS and list of installed packages via SSH login";

# See os_eol.inc for outdated / eol os versions. Please cross-check this file when updating here.
# Also update gather-package-list-docker-container.inc if adding a new OS.

OS_CPE = make_array(

    # OpenSUSE
    "openSUSELeap15.0", "cpe:/o:opensuse:leap:15.0",
    "openSUSELeap42.3", "cpe:/o:opensuse:leap:42.3",
    "openSUSELeap42.2", "cpe:/o:opensuse:leap:42.2",
    "openSUSELeap42.1", "cpe:/o:opensuse:leap:42.1",
    "openSUSELeap42.0", "cpe:/o:opensuse:leap:42.0",
    "openSUSE13.2", "cpe:/o:novell:opensuse:13.2",
    "openSUSE13.1", "cpe:/o:novell:opensuse:13.1",
    "openSUSE12.3", "cpe:/o:novell:opensuse:12.3",
    "openSUSE12.2", "cpe:/o:novell:opensuse:12.2",
    "openSUSE12.1", "cpe:/o:novell:opensuse:12.1",
    "openSUSE11.4", "cpe:/o:novell:opensuse:11.4",
    "openSUSE11.3", "cpe:/o:novell:opensuse:11.3",
    "openSUSE11.2", "cpe:/o:novell:opensuse:11.2",
    "openSUSE11.1", "cpe:/o:novell:opensuse:11.1",
    "openSUSE11.0", "cpe:/o:novell:opensuse:11.0",
    "openSUSE10.3", "cpe:/o:novell:opensuse:10.3",
    "openSUSE10.2", "cpe:/o:novell:opensuse:10.2",

    # SUSE Linux
    "SUSE10.1", "cpe:/o:novell:suse_linux:10.1",
    "SUSE10.0", "cpe:/o:novell:suse_linux:10.0",
    "SUSE9.3",  "cpe:/o:novell:suse_linux:9.3",
    "SUSE9.2",  "cpe:/o:novell:suse_linux:9.2",
    "SUSE9.1",  "cpe:/o:novell:suse_linux:9.1",
    "SUSE9.0",  "cpe:/o:novell:suse_linux:9.0",
    "SUSE8.2",  "cpe:/o:novell:suse_linux:8.2",
    "SUSE8.1",  "cpe:/o:novell:suse_linux:8.1",
    "SUSE8.0",  "cpe:/o:novell:suse_linux:8.0",
    "SUSE7.3",  "cpe:/o:novell:suse_linux:7.3",

    # SLES, https://en.wikipedia.org/wiki/SUSE_Linux_Enterprise_Server#Version_history
    "SLES15.0SP0", "cpe:/o:suse:linux_enterprise_server:15:SP0",
    "SLES12.0SP3", "cpe:/o:suse:linux_enterprise_server:12:SP3",
    "SLES12.0SP2", "cpe:/o:suse:linux_enterprise_server:12:SP2",
    "SLES12.0SP1", "cpe:/o:suse:linux_enterprise_server:12:SP1",
    "SLES12.0SP0", "cpe:/o:suse:linux_enterprise_server:12:SP0",
    "SLES11.0SP4", "cpe:/o:suse:linux_enterprise_server:11:SP4",
    "SLES11.0SP3", "cpe:/o:suse:linux_enterprise_server:11:SP3",
    "SLES11.0SP2", "cpe:/o:suse:linux_enterprise_server:11:SP2",
    "SLES11.0SP1", "cpe:/o:suse:linux_enterprise_server:11:SP1",
    "SLES11.0", "cpe:/o:suse:linux_enterprise_server:11",
    "SLES10.0", "cpe:/o:suse:linux_enterprise_server:10",
    "SLES9.0",  "cpe:/o:suse:linux_enterprise_server:9",
    "SLES8.0",  "cpe:/o:suse:linux_enterprise_server:8",
    "SLES7.0",  "cpe:/o:suse:linux_enterprise_server:7",

    # SLED, via https://download.suse.com/patch/finder/
    "SLED12.0SP3", "cpe:/o:suse:linux_enterprise_desktop:12:SP3",
    "SLED12.0SP2", "cpe:/o:suse:linux_enterprise_desktop:12:SP2",
    "SLED12.0SP1", "cpe:/o:suse:linux_enterprise_desktop:12:SP1",
    "SLED12.0SP0", "cpe:/o:suse:linux_enterprise_desktop:12:SP0",
    "SLED11.0SP4", "cpe:/o:suse:linux_enterprise_desktop:11:SP4",
    "SLED11.0SP3", "cpe:/o:suse:linux_enterprise_desktop:11:SP3",
    "SLED11.0SP2", "cpe:/o:suse:linux_enterprise_desktop:11:SP2",
    "SLED11.0SP1", "cpe:/o:suse:linux_enterprise_desktop:11:SP1",
    "SLED11.0SP0", "cpe:/o:suse:linux_enterprise_desktop:11:SP0",
    "SLED10.0SP4", "cpe:/o:suse:linux_enterprise_desktop:10:SP4",
    "SLED10.0SP3", "cpe:/o:suse:linux_enterprise_desktop:10:SP3",
    "SLED10.0SP2", "cpe:/o:suse:linux_enterprise_desktop:10:SP2",
    "SLED10.0SP1", "cpe:/o:suse:linux_enterprise_desktop:10:SP1",
    "SLED10.0SP0", "cpe:/o:suse:linux_enterprise_desktop:10:SP0",

    # Ubuntu
    "UBUNTU19.04","cpe:/o:canonical:ubuntu_linux:19.04",
    "UBUNTU18.10","cpe:/o:canonical:ubuntu_linux:18.10",
    "UBUNTU18.04 LTS","cpe:/o:canonical:ubuntu_linux:18.04:-:lts",
    "UBUNTU17.10",    "cpe:/o:canonical:ubuntu_linux:17.10",
    "UBUNTU17.04",    "cpe:/o:canonical:ubuntu_linux:17.04",
    "UBUNTU16.10",    "cpe:/o:canonical:ubuntu_linux:16.10",
    "UBUNTU16.04 LTS","cpe:/o:canonical:ubuntu_linux:16.04:-:lts",
    "UBUNTU15.10",    "cpe:/o:canonical:ubuntu_linux:15.10",
    "UBUNTU15.04",    "cpe:/o:canonical:ubuntu_linux:15.04",
    "UBUNTU14.10",    "cpe:/o:canonical:ubuntu_linux:14.10",
    "UBUNTU14.04 LTS","cpe:/o:canonical:ubuntu_linux:14.04:-:lts",
    "UBUNTU13.10",    "cpe:/o:canonical:ubuntu_linux:13.10",
    "UBUNTU13.04",    "cpe:/o:canonical:ubuntu_linux:13.04",
    "UBUNTU12.10",    "cpe:/o:canonical:ubuntu_linux:12.10",
    "UBUNTU12.04 LTS","cpe:/o:canonical:ubuntu_linux:12.04",
    "UBUNTU11.10",    "cpe:/o:canonical:ubuntu_linux:11.10",
    "UBUNTU11.04",    "cpe:/o:canonical:ubuntu_linux:11.04",
    "UBUNTU10.10",    "cpe:/o:canonical:ubuntu_linux:10.10",
    "UBUNTU10.04 LTS","cpe:/o:canonical:ubuntu_linux:10.04:-:lts",
    "UBUNTU9.10",     "cpe:/o:canonical:ubuntu_linux:9.10",
    "UBUNTU9.04",     "cpe:/o:canonical:ubuntu_linux:9.04",
    "UBUNTU8.10",     "cpe:/o:canonical:ubuntu_linux:8.10",
    "UBUNTU8.04 LTS", "cpe:/o:canonical:ubuntu_linux:8.04:-:lts",
    "UBUNTU7.10",     "cpe:/o:canonical:ubuntu_linux:7.10",
    "UBUNTU7.04",     "cpe:/o:canonical:ubuntu_linux:7.04",
    "UBUNTU6.10",     "cpe:/o:canonical:ubuntu_linux:6.10",
    "UBUNTU6.06 LTS", "cpe:/o:canonical:ubuntu_linux:6.06:-:lts",
    "UBUNTU5.10",     "cpe:/o:canonical:ubuntu_linux:5.10",
    "UBUNTU5.04",     "cpe:/o:canonical:ubuntu_linux:5.04",
    "UBUNTU4.1",      "cpe:/o:canonical:ubuntu_linux:4.10",

    # RHEL
    "RHENT_7",    "cpe:/o:redhat:enterprise_linux:7",
    "RHENT_6",    "cpe:/o:redhat:enterprise_linux:6",
    "RHENT_5",    "cpe:/o:redhat:enterprise_linux:5",
    "RHENT_4",    "cpe:/o:redhat:enterprise_linux:4",
    "RHENT_3",    "cpe:/o:redhat:enterprise_linux:3",
    "RHENT_2.1",  "cpe:/o:redhat:enterprise_linux:2.1",

    # Redhat Linux
    "RH9",    "cpe:/o:redhat:linux:9",
    "RH8.0",  "cpe:/o:redhat:linux:8.0",
    "RH7.3",  "cpe:/o:redhat:linux:7.3",

    # CentOS
    "CentOS7", "cpe:/o:centos:centos:7",
    "CentOS6", "cpe:/o:centos:centos:6",
    "CentOS5", "cpe:/o:centos:centos:5",
    "CentOS4", "cpe:/o:centos:centos:4",
    "CentOS3", "cpe:/o:centos:centos:3",
    "CentOS2", "cpe:/o:centos:centos:2",

    # Fedora / Fedora Core
    "FC30", "cpe:/o:fedoraproject:fedora:30",
    "FC29", "cpe:/o:fedoraproject:fedora:29",
    "FC28", "cpe:/o:fedoraproject:fedora:28",
    "FC27", "cpe:/o:fedoraproject:fedora:27",
    "FC26", "cpe:/o:fedoraproject:fedora:26",
    "FC25", "cpe:/o:fedoraproject:fedora:25",
    "FC24", "cpe:/o:fedoraproject:fedora:24",
    "FC23", "cpe:/o:fedoraproject:fedora:23",
    "FC22", "cpe:/o:fedoraproject:fedora:22",
    "FC21", "cpe:/o:fedoraproject:fedora:21",
    "FC20", "cpe:/o:fedoraproject:fedora:20",
    "FC19", "cpe:/o:fedoraproject:fedora:19",
    "FC18", "cpe:/o:fedoraproject:fedora:18",
    "FC17", "cpe:/o:fedoraproject:fedora:17",
    "FC16", "cpe:/o:fedoraproject:fedora:16",
    "FC15", "cpe:/o:fedoraproject:fedora:15",
    "FC14", "cpe:/o:fedoraproject:fedora:14",
    "FC13", "cpe:/o:fedoraproject:fedora:13",
    "FC12", "cpe:/o:fedoraproject:fedora:12",
    "FC11", "cpe:/o:fedoraproject:fedora:11",
    "FC10", "cpe:/o:fedoraproject:fedora:10",
    "FC9",  "cpe:/o:fedoraproject:fedora:9",
    "FC8",  "cpe:/o:fedoraproject:fedora:8",
    "FC7",  "cpe:/o:fedoraproject:fedora:7",
    "FC6",  "cpe:/o:fedoraproject:fedora_core:6",
    "FC5",  "cpe:/o:fedoraproject:fedora_core:5",
    "FC4",  "cpe:/o:fedoraproject:fedora_core:4",
    "FC3",  "cpe:/o:fedoraproject:fedora_core:3",
    "FC2",  "cpe:/o:fedoraproject:fedora_core:2",
    "FC1",  "cpe:/o:fedoraproject:fedora_core:1",

    # Mandriva
    "MNDK_2011.0",  "cpe:/o:mandriva:linux:2011.0",
    "MNDK_2010.2",  "cpe:/o:mandriva:linux:2010.2",
    "MNDK_2010.1",  "cpe:/o:mandriva:linux:2010.1",
    "MNDK_2010.0",  "cpe:/o:mandriva:linux:2010.0",
    "MNDK_2009.1",  "cpe:/o:mandriva:linux:2009.1",
    "MNDK_2009.0",  "cpe:/o:mandriva:linux:2009.0",
    "MNDK_2008.1",  "cpe:/o:mandriva:linux:2008.1",
    "MNDK_2008.0",  "cpe:/o:mandriva:linux:2008.0",
    "MNDK_2007.1",  "cpe:/o:mandriva:linux:2007.1",
    "MNDK_2007.0",  "cpe:/o:mandriva:linux:2007.0",
    "MNDK_2006.0",  "cpe:/o:mandriva:linux:2006.0",
    "MNDK_mes5.2",  "cpe:/o:mandriva:enterprise_server:5.2",
    "MNDK_mes5.1",  "cpe:/o:mandriva:enterprise_server:5.1",
    "MNDK_mes5.0",  "cpe:/o:mandriva:enterprise_server:5.0", # Keep both for backward compatibility
    "MNDK_mes5",    "cpe:/o:mandriva:enterprise_server:5", # Keep both for backward compatibility

    # Mandrake
    "MNDK_10.1",    "cpe:/o:mandrakesoft:mandrake_linux:10.1",
    "MNDK_10.0",    "cpe:/o:mandrakesoft:mandrake_linux:10.0",
    "MNDK_9.2",     "cpe:/o:mandrakesoft:mandrake_linux:9.2",
    "MNDK_9.1",     "cpe:/o:mandrakesoft:mandrake_linux:9.1",
    "MNDK_9.0",     "cpe:/o:mandrakesoft:mandrake_linux:9.0",
    "MNDK_8.2",     "cpe:/o:mandrakesoft:mandrake_linux:8.2",
    "MNDK_8.1",     "cpe:/o:mandrakesoft:mandrake_linux:8.1",
    "MNDK_8.0",     "cpe:/o:mandrakesoft:mandrake_linux:8.0",
    "MNDK_7.2",     "cpe:/o:mandrakesoft:mandrake_linux:7.2",

    #Mageia
    "MAGEIA6",     "cpe:/o:mageia:linux:6",
    "MAGEIA5",     "cpe:/o:mageia:linux:5",
    "MAGEIA4.1",   "cpe:/o:mageia:linux:4.1",
    "MAGEIA4",     "cpe:/o:mageia:linux:4",
    "MAGEIA3",     "cpe:/o:mageia:linux:3",
    "MAGEIA2",     "cpe:/o:mageia:linux:2",
    "MAGEIA1",     "cpe:/o:mageia:linux:1",

    # Slackware
    "SLK14.2", "cpe:/o:slackware:slackware_linux:14.2",
    "SLK14.1", "cpe:/o:slackware:slackware_linux:14.1",
    "SLK14.0", "cpe:/o:slackware:slackware_linux:14.0",
    "SLK13.37", "cpe:/o:slackware:slackware_linux:13.37",
    "SLK13.1", "cpe:/o:slackware:slackware_linux:13.1",
    "SLK13.0", "cpe:/o:slackware:slackware_linux:13.0",
    "SLK12.2", "cpe:/o:slackware:slackware_linux:12.2",
    "SLK12.1", "cpe:/o:slackware:slackware_linux:12.1",
    "SLK12.0", "cpe:/o:slackware:slackware_linux:12.0",
    "SLK11.0", "cpe:/o:slackware:slackware_linux:11.0",
    "SLK10.2", "cpe:/o:slackware:slackware_linux:10.2",
    "SLK10.1", "cpe:/o:slackware:slackware_linux:10.1",
    "SLK10.0", "cpe:/o:slackware:slackware_linux:10.0",
    "SLK9.1",  "cpe:/o:slackware:slackware_linux:9.1",
    "SLK9.0",  "cpe:/o:slackware:slackware_linux:9.0",
    "SLK8.1",  "cpe:/o:slackware:slackware_linux:8.1",
    "SLK8.0",  "cpe:/o:slackware:slackware_linux:8.0",
    "SLK7.1",  "cpe:/o:slackware:slackware_linux:7.1",
    "SLK7.0",  "cpe:/o:slackware:slackware_linux:7.0",
    "SLK4.0",  "cpe:/o:slackware:slackware_linux:4.0",
    "SLK3.9",  "cpe:/o:slackware:slackware_linux:3.9",
    "SLK3.6",  "cpe:/o:slackware:slackware_linux:3.6",
    "SLK3.5",  "cpe:/o:slackware:slackware_linux:3.5",
    "SLK3.4",  "cpe:/o:slackware:slackware_linux:3.4",
    "SLK3.3",  "cpe:/o:slackware:slackware_linux:3.3",
    "SLK3.2",  "cpe:/o:slackware:slackware_linux:3.2",
    "SLK3.1",  "cpe:/o:slackware:slackware_linux:3.1",
    "SLK3.0",  "cpe:/o:slackware:slackware_linux:3.0",
    "SLK2.3",  "cpe:/o:slackware:slackware_linux:2.3",
    "SLK2.2",  "cpe:/o:slackware:slackware_linux:2.2",
    "SLK2.1",  "cpe:/o:slackware:slackware_linux:2.1",
    "SLK2.0",  "cpe:/o:slackware:slackware_linux:2.0",
    "SLK1.1",  "cpe:/o:slackware:slackware_linux:1.1",
    "SLK1.00",  "cpe:/o:slackware:slackware_linux:1.00",

    # Connectiva Linux
    "CL10", "cpe:/a:connectiva:linux:10.0",
    "CL9",  "cpe:/a:connectiva:linux:9.0",

    # Amazon Linux
    "AMAZON",     "cpe:/o:amazon:linux",

    # Univention Corporate Server (http://wiki.univention.de/index.php?title=Maintenance_Cycle_for_UCS)
    "UCS4.2", "cpe:/o:univention:univention_corporate_server:4.2",
    "UCS4.1", "cpe:/o:univention:univention_corporate_server:4.1",
    "UCS4.0", "cpe:/o:univention:univention_corporate_server:4.0",
    "UCS3.3", "cpe:/o:univention:univention_corporate_server:3.3",
    "UCS3.2", "cpe:/o:univention:univention_corporate_server:3.2",
    "UCS3.1", "cpe:/o:univention:univention_corporate_server:3.1",
    "UCS3.0", "cpe:/o:univention:univention_corporate_server:3.0",
    "UCS2.4", "cpe:/o:univention:univention_corporate_server:2.4",
    "UCS2.3", "cpe:/o:univention:univention_corporate_server:2.3",
    "UCS2.2", "cpe:/o:univention:univention_corporate_server:2.2",
    "UCS2.1", "cpe:/o:univention:univention_corporate_server:2.1",
    "UCS2.0", "cpe:/o:univention:univention_corporate_server:2.0",

    # Turbo Linux
    "TLS7", "cpe:/o:turbolinux:turbolinux_server:7.0",
    "TLWS7", "cpe:/o:turbolinux:turbolinux_workstation:7.0",
    "TLS8", "cpe:/o:turbolinux:turbolinux_server:8.0",
    "TLWS8", "cpe:/o:turbolinux:turbolinux_workstation:8.0",
    "TLDT10", "cpe:/o:turbolinux:turbolinux_desktop:10.0",
    "TLS10", "cpe:/o:turbolinux:turbolinux_server:10.0",

    # Trustix
    "TSL3.0.5", "cpe:/o:trustix:secure_linux:3.0.5",
    "TSL3.0",   "cpe:/o:trustix:secure_linux:3.0",
    "TSL2.2",   "cpe:/o:trustix:secure_linux:2.2",
    "TSL2.1",   "cpe:/o:trustix:secure_linux:2.1",
    "TSL2.0",   "cpe:/o:trustix:secure_linux:2.0",
    "TSL1.5",   "cpe:/o:trustix:secure_linux:1.5",
    "TSL1.2",   "cpe:/o:trustix:secure_linux:1.2",
    "TSL1.1",   "cpe:/o:trustix:secure_linux:1.1",

    # Gentoo
    "GENTOO", "cpe:/o:gentoo:linux",

    # HP-UX
    "HPUX11.31", "cpe:/o:hp:hp-ux:11.31",
    "HPUX11.23", "cpe:/o:hp:hp-ux:11.23",
    "HPUX11.22", "cpe:/o:hp:hp-ux:11.22",
    "HPUX11.20", "cpe:/o:hp:hp-ux:11.20",
    "HPUX11.11", "cpe:/o:hp:hp-ux:11.11",
    "HPUX11.10", "cpe:/o:hp:hp-ux:11.10",
    "HPUX11.04", "cpe:/o:hp:hp-ux:11.04",
    "HPUX11.00", "cpe:/o:hp:hp-ux:11.00",
    "HPUX10.30", "cpe:/o:hp:hp-ux:10.30",
    "HPUX10.26", "cpe:/o:hp:hp-ux:10.26",
    "HPUX10.24", "cpe:/o:hp:hp-ux:10.24",
    "HPUX10.20", "cpe:/o:hp:hp-ux:10.20",
    "HPUX10.10", "cpe:/o:hp:hp-ux:10.10",
    "HPUX10.01", "cpe:/o:hp:hp-ux:10.01",

    # FortiOS
    "FortiOS", "cpe:/o:fortinet:fortios",

    # Arch Linux
    # nb: Arch Linux is a rolling release so there is no "real" version
    "ArchLinux", "cpe:/o:archlinux:archlinux"
);

# GNU/Linux platforms:
function register_detected_os( os, oskey ) {

  if( ! isnull( oskey ) )
    set_kb_item( name:"ssh/login/release", value:oskey );

  if( ! isnull( oskey ) && ! isnull( OS_CPE[oskey] ) ) {
    register_and_report_os( os:os, cpe:OS_CPE[oskey], banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:os, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

function register_packages( buf ) {
  set_kb_item( name:"ssh/login/packages", value:buf );
}

function register_rpms( buf ) {
  set_kb_item( name:"ssh/login/rpms", value:";" + buf );
}

function register_uname( uname ) {
  local_var uname;
  replace_kb_item( name:"ssh/login/uname", value:uname );
  replace_kb_item( name:"Host/uname", value:uname );
}

port = kb_ssh_transport();
sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

# First command: Grab uname -a of the remote system
uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:TRUE, pty:TRUE, timeout:60, retry:30 );
if( isnull( uname ) ) exit( 0 );

# HP iLO 100:
# Lights-Out 100 Management
# Copyright 2005-2007 ServerEngines Corporation
# Copyright 2006-2007 Hewlett-Packard Development Company, L.P.
#
# /./-> Invalid command
#
# https://blog.marquis.co/how-to-access-hps-ilo-remote-console-via-ssh/
#
# User:Administrator logged-in to ILO----n.(10.2.0.21)
# iLO 2 Standard Blade Edition 2.25 at 16:36:26 Apr 14 2014
# Server Name: vMX-Bay1
# Server Power: On
#
# hpiLO->
#
# https://community.hpe.com/t5/ProLiant-Servers-ML-DL-SL/SOLVED-Cannot-SSH-into-ILO4-v1-40-or-v1-50-after-upgrading-from/td-p/6505622
#
# User:Administrator logged-in to MYHOSTNAME(X.X.X.X / IPv6)
# iLO 4 Advanced 1.50 at  May 07 2014
# Server Name: MYHOSTNAME
# Server Power: On
#
# hpiLO->
#
# User:Administrator logged-in to MYHOSTNAME(X.X.X.X / IPv6)
# iLO 3 Advanced 1.70 at  May 07 2014
# Server Name: MYHOSTNAME
# Server Power: On
#
# hpiLO->
#
if( ( uname =~ "Lights-Out.*Management" && ( uname =~ "Copyright .+ ServerEngines Corporation" ||
                                             uname =~ "Copyright .+ Hewlett-Packard Development Company" ||
                                             "/./-> Invalid command" >< uname ) ) ||
    ( " logged-in to " >< uname && ( uname =~ "iLO [0-9]" || "hpiLO->" >< uname ) ) ) {

  # https://community.hpe.com/t5/ProLiant-Servers-ML-DL-SL/System-Firmware-Version-ssh-through-iLO/td-p/1151731
  # ftp://ftp.mrynet.com/operatingsystems/HP-MPE/docs.hp.com/en/AH232-9008A-ed3/apbs07.html
  # SYSREV should print out something like:
  # FIRMWARE INFORMATION
  #
  #    MP FW: H.03.15
  #    BMC FW: 04.05
  #    EFI FW: 05.16
  #    System FW: 62.14
  sysrev = ssh_cmd( socket:sock, cmd:"SYSREV", nosh:TRUE, return_errors:FALSE, pty:TRUE, timeout:20, retry:10 );
  if( sysrev )
    register_unknown_os_banner( banner:'HP iLO response to the "SYSREV" command:\n\n' + sysrev, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );

  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  exit( 0 );
}

# Initial setup:
# Welcome to the TippingPoint Technologies SMS Initial Setup wizard.
#
# Configured device:
# Welcome to TippingPoint Technologies SMS !
if( _uname = egrep( pattern:"Welcome to (the )?TippingPoint Technologies SMS", string:uname ) ) {

  version = ssh_cmd( socket:sock, cmd:"version", nosh:TRUE, return_errors:FALSE, pty:TRUE, timeout:20, retry:10, pattern:"Version:" );

  # Version:
  #     5.0.0.106258
  #
  # Patch:
  #     5.0.0.106258.1
  if( "Version:" >< version )
    set_kb_item( name:"tippingpoint/sms/ssh-login/" + port + "/version_cmd", value:version );

  set_kb_item( name:"tippingpoint/sms/ssh-login/" + port + "/uname", value:chomp( _uname ) );
  set_kb_item( name:"tippingpoint/sms/ssh-login/version_cmd_or_uname", value:TRUE );
  set_kb_item( name:"tippingpoint/sms/ssh-login/port", value:port );

  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  exit( 0 );
}

if( "HyperIP Command Line Interface" >< uname ) {

  replace_kb_item( name:"ssh/send_extra_cmd", value:'\n' );
  show_version = ssh_cmd( socket:sock, cmd:"showVersion", nosh:TRUE, return_errors:FALSE, pty:TRUE, timeout:20, retry:10, pattern:"Product Version" );

  # Product Version ............ HyperIP 6.1.1 11-Jan-2018 13:09 (build 2) (r9200)
  if( "Product Version" >< show_version && "HyperIP" >< show_version )
    set_kb_item( name:"hyperip/ssh-login/" + port + "/show_version", value:show_version );

  set_kb_item( name:"hyperip/ssh-login/" + port + "/uname", value:uname );
  set_kb_item( name:"hyperip/ssh-login/show_version_or_uname", value:TRUE );
  set_kb_item( name:"hyperip/ssh-login/port", value:port );

  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  exit( 0 );
}

# NetApp Data ONTAP 9.x
# hostname::>
# Error: "/bin/sh" is not a recognized command
#
# or:
# hostname::*>
# Error: "/bin/sh" is not a recognized command

# NetApp Data ONTAP 7.x
# hostname>
# /bin/sh not found.  Type '?' for a list of commands

if( _uname = eregmatch( string:uname, pattern:'^.+(::\\*?> \nError: "[^"]+" is not a recognized command|>.+not found\\.  Type \'\\?\' for a list of commands)', icase:FALSE ) ) {

  version = ssh_cmd( socket:sock, cmd:"version", nosh:TRUE, return_errors:FALSE, pty:TRUE, timeout:20, retry:10, pattern:"NetApp Release" );

  # NetApp Release 9.0: Fri Aug 19 06:39:33 UTC 2016
  # NetApp Release 7.3: Thu Jul 24 12:55:28 PDT 2008
  if( "NetApp Release" >< version )
    set_kb_item( name:"netapp_data_ontap/ssh-login/" + port + "/version_cmd", value:version );

  set_kb_item( name:"netapp_data_ontap/ssh-login/" + port + "/uname", value:chomp( _uname[0] ) );
  set_kb_item( name:"netapp_data_ontap/ssh-login/version_cmd_or_uname", value:TRUE );
  set_kb_item( name:"netapp_data_ontap/ssh-login/port", value:port );

  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  exit( 0 );
}

# e.g. Cisco Prime Infrastructure if another admin is logged in
if( "Another user is logged into the system at this time" >< uname && "Are you sure you want to continue" >< uname ) {
  replace_kb_item( name:"ssh/send_extra_cmd", value:'Yes\n' );
  uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:TRUE, pty:TRUE, timeout:20, retry:10 );
}

if( "Following disconnected ssh sessions are available to resume" >< uname ) {
  replace_kb_item( name:"ssh/send_extra_cmd", value:'\n' );
  uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:TRUE, pty:TRUE, timeout:20, retry:10 );
}

if( "Welcome to Data Domain OS" >< uname ) {
  set_kb_item( name:"emc/data_domain_os/uname", value:uname );
  log_message( port:port, data:'We are able to login and detect that you are running EMC Data Domain OS');
  exit( 0 );
}

if( "Welcome to pfSense" >< uname ) {
  set_kb_item( name:"pfsense/uname", value:uname );
  set_kb_item( name:"pfsense/ssh/port", value:port);
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  set_kb_item( name:"ssh/force/nosh", value:TRUE );
  # clear the buffer to avoid that we're saving the whole pfSense menu in the uname
  set_kb_item( name:"ssh/force/clear_buffer", value:TRUE );
  replace_kb_item( name:"ssh/send_extra_cmd", value:'8\n' );
  uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:TRUE, pty:TRUE, timeout:20, retry:10 );
  # nb: FreeBSD will be caught later below
}

if( "Welcome to the Greenbone OS" >< uname ) {
  set_kb_item( name:"greenbone/gos/uname", value:uname );
  set_kb_item( name:"greenbone/gos", value:TRUE );

  # Don't use a pty which avoids that we're getting the GOS admin menu back in our uname command
  # and to save the "real" uname later
  uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:FALSE, pty:FALSE, timeout:20, retry:10 );

  # This is from GOS 3.1.x where we need to use a pty and pass an extra command for each ssh_cmd call
  if( "Type 'gos-admin-menu' to start the Greenbone OS Administration tool" >< uname ) {
    replace_kb_item( name:"ssh/send_extra_cmd", value:'shell\n' );
    uname = ssh_cmd( socket:sock, cmd:"uname -a", return_errors:FALSE, pty:TRUE, timeout:20, retry:10 );
  }
}

if( "linux" >< tolower( uname ) ) {
  un = egrep( pattern:'(Linux[^\r\n]+)', string:uname );
  if( un ) {
    u = eregmatch( pattern:'(Linux [^ ]+ [^ ]+ #[0-9]+ [^\n]+)', string:un );

    if( ! isnull( u[1] ) ) {
      register_uname( uname:u[1] );
    }
  }
}

if( "(Cisco Controller)" >< uname )
  exit( 0 );

# To catch the uname above before doing an exit
if( get_kb_item( "greenbone/gos" ) )
  exit( 0 );

# nb: It wasn't clear if this was only seen on GOS so keep this for now.
# nb2: This exists at least on TippingPoint Security Management System (SMS) as well.
if( "restricted: cannot specify" >< uname ) {
  set_kb_item( name:"ssh/restricted_shell", value:TRUE );
  exit( 0 );
}

if( "TANDBERG Video Communication Server" >< uname ) {
  set_kb_item( name:"cisco/ssh/vcs", value:TRUE );
  set_kb_item( name:"ssh/send_extra_cmd", value:'\n' );
  exit( 0 );
}

if( "Cyberoam Central Console" >< uname )
{
  set_kb_item( name:"cyberoam_cc/detected", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );

  ccc = eregmatch( pattern:'([0-9]+)\\.\\s*CCC Console', string:uname );
  if( ! isnull( ccc[1] ) )
  {
    version_info = ssh_cmd( socket:sock, cmd:ccc[1] + '\nccc diagnostics show version-info', nosh:TRUE, pty:TRUE, timeout:60, retry:20, pattern:"Hot Fix version" );
    if( "CCC version:" >< version_info )
      set_kb_item( name:"cyberoam_cc/version_info", value:version_info );
  }
  exit( 0 );
}

if( "Welcome to the Immediate Insight Management Console" >< uname || ( "type 'start' to start the server" >< uname && "'status' checks the current setup" >< uname ) )
{
  set_kb_item( name:"firemon/immediate_insight/detected", value:TRUE );
  exit( 0 );
}

if( 'Error: Unknown: "/bin/sh"' >< uname )
{
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  set_kb_item( name:"enterasys/detected", value:TRUE );
  exit( 0 );
}

if( "Cisco UCS Director Shell Menu" >< uname )
{
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );

  v = eregmatch( pattern:'([0-9]+)\\) Show Version', string:uname );
  if( ! isnull( v[1] ) )
  {
    show_version = ssh_cmd( socket:sock, cmd:v[1], nosh:TRUE, pty:TRUE, timeout:60, retry:20, pattern:"Press return to continue" );
    if( show_version && "Version" >< show_version && "Build" >< show_version )
    {
      set_kb_item( name:"cisco_ucs_director/show_version", value:show_version );
      exit( 0 );
    }
  }
}

if( "% invalid command at '^' marker" >< tolower( uname ) || "No token match at '^' marker" >< uname ||
    "NX-OS" >< uname || "Cisco Nexus Operating System" >< uname || "Line has invalid autocommand" >< uname )
{
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  set_kb_item( name:"cisco/detected", value:TRUE );

  # The CISCO device is closing the connection after this message.
  # Unfortunately we can't detect if the device has configured a working autocommand but we still
  # want to report a broken one to the user (in 2017/gb_ssh_authentication_info.nasl).
  if( "Line has invalid autocommand" >< uname ) set_kb_item( name:"ssh/cisco/broken_autocommand", value:TRUE );

  exit( 0 );
}

if( "Command Line Interface is starting up" >< uname || "Invalid command, a dash character must be preceded" >< uname )
{
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );

  system = ssh_cmd( socket:sock, cmd:'show tech ccm_service', nosh:TRUE, pty:TRUE, timeout:60, retry:50 );

  if( "GroupName: CM Services" >< system )
  {
    set_kb_item( name:"cisco/cucm/show_tech_ccm_service", value:system );
    set_kb_item( name:"cisco/cucm/detected", value:TRUE );
    exit( 0 );
  }

  if( "GroupName: IM and Presence Services" >< system )
  {
    set_kb_item( name:"cisco/cucmim/show_tech_ccm_service", value:system );
    set_kb_item( name:"cisco/cucmim/detected", value:TRUE );
    exit( 0 );
  }

  if( "GroupName: Cisco Finesse Services" >< system )
  {
    set_kb_item( name:"cisco/finesse/show_tech_ccm_service", value:system );
    set_kb_item( name:"cisco/finesse/detected", value:TRUE );
    exit( 0 );
  }
  exit( 0 );
}

if( uname =~ "Cisco Prime( Virtual)? Network Analysis Module" )
{
  show_ver = ssh_cmd( socket:sock, cmd:'show version', nosh:TRUE, pty:TRUE, timeout:30, retry:10, pattern:'Installed patches:' );
  if( "NAM application image" >< show_ver )
  {
    set_kb_item( name:"cisco_nam/show_ver", value:show_ver );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    exit( 0 );
  }
}

if( "CMC Build" >< uname && "LEM" >< uname && "Exit CMC" >< uname )
{
  set_kb_item( name:"solarwinds_lem/installed", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  sysinfo = ssh_cmd( socket:sock, cmd:'manager\nviewsysinfo', nosh:TRUE, pty:TRUE, timeout:90, retry:10, pattern:'/tmp/swi-lem-sysinfo.txt' );
  vers = eregmatch( pattern:'TriGeo manager version is: ([^\r\n]+)', string:sysinfo );
  if( ! isnull( vers[1] ) ) set_kb_item( name:"solarwinds_lem/version/ssh", value:vers[1] );

  build = eregmatch( pattern:'TriGeo manager build is: ([^\r\n]+)', string: sysinfo );
  if( ! isnull( build[1] ) )
  {
    set_kb_item( name:"solarwinds_lem/build/ssh", value:build[1] );
    hotfix = eregmatch( pattern:'hotfix([0-9]+)', string:build[1] );
    if( ! isnull( hotfix[1] ) ) set_kb_item( name:"solarwinds_lem/hotfix/ssh", value:hotfix[1] );
  }

  ubuild =  eregmatch( pattern:'TriGeo upgrade build is: ([^\r\n]+)', string: sysinfo );
  if( ! isnull( ubuild[1] ) ) set_kb_item( name:"solarwinds_lem/ubuild/ssh", value:ubuild[1] );

  cmc = eregmatch( pattern:'CMC version: ([^\r\n]+)', string:sysinfo );
  if( ! isnull( cmc[1] ) ) set_kb_item( name:"solarwinds_lem/cmc_version/ssh", value:cmc[1] );

  exit( 0 );
}

if( "Sourcefire Linux OS" >< uname )
{
  set_kb_item( name:"sourcefire_linux_os/installed", value:TRUE );

  cpe = 'cpe:/o:sourcefire:linux_os';
  version = eregmatch( pattern:'Sourcefire Linux OS v([^ ]+)', string:uname );

  if( ! isnull( version[1] ) )
  {
    cpe += ':' + version[1];
    set_kb_item( name:"sourcefire_linux_os/version", value:version[1] );
  }

  build = eregmatch( pattern:'\\(build ([^)]+)\\)', string:uname );

  if( ! isnull( build[1] ) ) set_kb_item( name:"sourcefire_linux_os/build", value:build[1] );

  register_and_report_os( os:"Sourcefire Linux OS", cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

  report = 'We are able to login and detect that you are running Sourcefire Linux OS';

  if( version[1] ) report += '\nVersion: ' + version[1];
  if( build[1] ) report += '\nBuild: ' + build[1];

  log_message( port:port, data:report );
  exit( 0 );
}

if( "Cisco Firepower Management Center" >< uname )
{
  set_kb_item( name:'cisco_fire_linux_os/detected', value:TRUE );
  if( "Cisco Fire Linux OS" >< uname )
  {
    cpe = 'cpe:/o:cisco:fire_linux_os';
    version = eregmatch( pattern:'Cisco Fire Linux OS v([^ ]+)', string:uname );
    if( ! isnull( version[1] ) )
    {
      cpe += ':' + version[1];
      set_kb_item( name:"cisco/fire_linux_os/version", value:version[1] );
    }

    build = eregmatch( pattern:'\\(build ([^)]+)\\)', string: uname);
    if( ! isnull( build[1] ) ) set_kb_item( name:"cisco/fire_linux_os/build", value:build[1] );

    register_and_report_os( os:"Cisco Fire Linux OS", cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

    report = 'We are able to login and detect that you are running Cisco Fire Linux OS';

    if( version[1] ) report += '\nVersion: ' + version[1];
    if( build[1] ) report += '\nBuild: ' + build[1];

    log_message( port:port, data:report );
    exit( 0 );
  }
}

if( uname =~ "Cisco NGIPS(v)?" && "Cisco Fire Linux OS" >< uname )
{
  if( "Cisco Fire Linux OS" >< uname )
  {
    cpe = 'cpe:/o:cisco:fire_linux_os';
    version = eregmatch(pattern: 'Cisco Fire Linux OS v([^ ]+)', string: uname );
    if( ! isnull( version[1] ) )
    {
      cpe += ':' + version[1];
      set_kb_item(name: "cisco/fire_linux_os/version", value: version[1]);
    }

    build = eregmatch(pattern: '\\(build ([^)]+)\\)', string: uname);
    if( ! isnull( build[1] ) ) set_kb_item(name: "cisco/fire_linux_os/build", value: build[1] );

    register_and_report_os(os: "Cisco Fire Linux OS", cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );

    report = 'We are able to login and detect that you are running Cisco Fire Linux OS';

    if( version[1] ) report += '\nVersion: ' + version[1];
    if( build[1] ) report += '\nBuild: ' + build[1];

    log_message(port: port, data: report);
  }

  set_kb_item(name: "cisco/ngips/uname", value: uname);
  exit( 0 );
}

if( "CLINFR0329  Invalid command" >< uname )
{
  show_ver = ssh_cmd(socket: sock, cmd: "show version all", nosh: TRUE, return_errors: FALSE, pty: FALSE);
  if( show_ver && "Check Point Gaia" >< show_ver )
  {
    gaia_cpe = 'cpe:/o:checkpoint:gaia_os';
    set_kb_item(name: "checkpoint_fw/detected", value: TRUE);

    version = eregmatch(pattern: 'Product version Check Point Gaia (R[^\r\n]+)', string: show_ver);
    if( ! isnull( version[1] ) )
    {
      gaia_cpe += ':' + tolower(version[1]);
      set_kb_item(name: "checkpoint_fw/ssh/version", value: version[1]);
    }

    register_and_report_os(os: "Check Point Gaia", cpe: gaia_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );

    build = eregmatch(pattern: 'OS build ([^\r\n]+)', string: show_ver);
    if( ! isnull( build[1] ) ) set_kb_item( name:"checkpoint_fw/ssh/build", value:build[1] );

    report = 'We are able to login and detect that you are running Check Point Gaia.';

    if( version[1] ) report += '\nVersion: ' + version[1];
    if( build[1] ) report += '\nBuild: ' + build[1];

    log_message( port:port, data:report );
    exit( 0 );
  }
}

if( "% Unknown command" >< uname )
{
   show_ver = ssh_cmd( socket:sock, cmd:"show version", return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20, retry:10, pattern:"NSX Manager" );
   if( show_ver && "NSX Manager" >< show_ver )
   {
     set_kb_item( name:"vmware_nsx/show_ver", value:show_ver );
     set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
     set_kb_item( name:"ssh/force/pty", value:TRUE );
     set_kb_item( name:"vmware_nsx/detected_by", value:"SSH" );
     exit( 0 );
   }
}

if( "JUNOS" >< uname && "Junos Space" >!< uname )
{
  if( "unknown command" >< uname )
  {
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"junos/cli", value:TRUE );
  }
  set_kb_item( name:"junos/detected", value:TRUE );
  exit( 0 );
}

if( "Wedge Networks" >< uname && "BeSecure" >< uname && "To access the management console" >< uname )
{
  status = ssh_cmd( socket:sock, cmd:"status show", nosh:TRUE );
  if( "Scanner" >< status && "BeSecure" >< status )
  {
    set_kb_item( name:"wedgeOS/status", value:status );
    exit( 0 );
  }
}

if( 'ERROR: "/" not recognized' >< uname )
{
  sv = ssh_cmd( socket:sock, cmd:"show version", nosh:TRUE, pty:TRUE, pattern:"F5 Networks LROS Version" );
  if( "F5 Networks LROS Version" >< sv )
  {
    set_kb_item( name:"f5/LROS/show_version", value:sv );
    exit( 0 );
  }
}

if( "ERROR: No such command" >< uname )
{
  system = ssh_cmd( socket:sock, cmd:'show ns version', nosh:TRUE );
  if( "NetScaler" >< system )
  {
    set_kb_item( name:"citrix_netscaler/system", value: system );
    set_kb_item( name:"citrix_netscaler/found", value:TRUE );
    set_kb_item( name:"citrix_netscaler/ssh/port", value: port );

    hw = ssh_cmd( socket:sock, cmd:'show ns hardware', nosh:TRUE );
    if( hw )
      set_kb_item( name:"citrix_netscaler/hardware", value: hw );

    features = ssh_cmd( socket:sock, cmd:'show ns feature', nosh:TRUE  );
    if( features )
      set_kb_item( name:"citrix_netscaler/features", value: features );

   exit( 0 );
  }
}

if( "-----unknown keyword " >< uname )
{
  set_kb_item( name:"ScreenOS/detected", value:TRUE );
  exit( 0 );
}

if( "Unknown command:" >< uname && "IBM Security Network Protection" >< uname )
{
  set_kb_item( name:"isnp/detected", value:TRUE );
  set_kb_item( name:"ssh/force/pty", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  exit( 0 );
}

if( "Unknown command: " >< uname || "Unknown command or missing feature key" >< uname )
{
  system = ssh_cmd( socket:sock, cmd:'show system info', nosh:TRUE, pty:TRUE, pattern:"model: PA", retry:8 );
  if( eregmatch( pattern:'model: PA-', string:system ) && "family:" >< system )
  {
    set_kb_item( name:"palo_alto/detected", value:TRUE );
    set_kb_item( name:"palo_alto/ssh/detected", value:TRUE );
    set_kb_item( name:"palo_alto/ssh/port", value:port );
    set_kb_item( name:"palo_alto/ssh/" + port + "/system", value:system );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    exit( 0 );
  }

  system = ssh_cmd( socket:sock, cmd:'version', nosh:TRUE );
  if( ( "Cisco" >< system || "IronPort" >< system ) && system =~ 'Security( Virtual)? Management' )
  {

    set_kb_item( name:"cisco_csm/system", value:system );
    set_kb_item( name:"cisco_csm/installed", value:TRUE );

    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );

    version = eregmatch( pattern:'Version: ([^\r\n]+)', string:system );
    if( ! isnull( version[1] ) ) set_kb_item( name:"cisco_csm/version/ssh", value:version[1] );

    model = eregmatch( pattern:'Model: ([^\r\n]+)', string:system );
    if( ! isnull( model[1] ) ) set_kb_item( name:"cisco_csm/model/ssh", value:model[1] );

    exit( 0 );
  }

  if( ( "Cisco" >< system || "IronPort" >< system ) && system =~ 'Email Security( Virtual)? Appliance' )
  {
    set_kb_item( name:"cisco_esa/system", value:system );
    set_kb_item( name:"cisco_esa/installed", value:TRUE );

    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );

    version = eregmatch( pattern:'Version: ([^\r\n]+)', string:system );
    if( ! isnull( version[1] ) ) set_kb_item( name:"cisco_esa/version/ssh", value:version[1] );

    model = eregmatch( pattern:'Model: ([^\r\n]+)', string:system );
    if( ! isnull( model[1] ) ) set_kb_item( name:"cisco_esa/model/ssh", value:model[1] );

    exit( 0 );
  }

  if( ( "Cisco" >< system || "IronPort" >< system ) && system =~ 'Web Security( Virtual)? Appliance' )
  {
    set_kb_item( name:"cisco_wsa/system", value:system );
    set_kb_item( name:"cisco_wsa/installed", value:TRUE );

    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );

    version = eregmatch( pattern:'Version: ([^\r\n]+)', string:system );
    if( ! isnull( version[1] ) ) set_kb_item( name:"cisco_wsa/version/ssh", value:version[1] );

    model = eregmatch( pattern:'Model: ([^\r\n]+)', string:system );
    if( ! isnull( model[1] ) ) set_kb_item( name:"cisco_wsa/model/ssh", value:model[1] );

    exit( 0 );
  }
}

if( ( "diagnose" >< uname || "traceroute6" >< uname ) && "enable" >< uname && "exit" >< uname && "^" >< uname)
{
  system = ssh_cmd( socket:sock, cmd:'show system version', nosh:TRUE, pty:FALSE );
  if( "Operating System" >< system && "IWSVA" >< system )
  {
    set_kb_item( name:"IWSVA/system", value:system);
    set_kb_item( name:"IWSVA/cli_is_clish", value:TRUE);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    exit( 0 );
  }

  system = ssh_cmd( socket:sock, cmd:'show module IMSVA version', nosh:TRUE, pty:FALSE );

  if( system =~ "IMSVA [0-9.]+-Build_Linux_[0-9]+" )
  {
    set_kb_item( name:"IMSVA/system", value:system);
    set_kb_item( name:"IMSVA/cli_is_clish", value:TRUE);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    exit( 0 );
  }

}

if( "Invalid input detected at" >< uname )
{
  set_kb_item( name:"cisco/detected", value:TRUE );
  set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  exit( 0 );
}

if( "% invalid command detected" >< uname )
{
  show_ver = ssh_cmd( socket:sock, cmd:'show version', nosh:TRUE, pty:TRUE, pattern:"Internal Build", timeout:60, retry:20 );
  if( "ERROR : Please enter Yes or No" >< show_ver )
    show_ver = ssh_cmd( socket:sock, cmd:'Yes\nshow version', nosh:TRUE, pty:TRUE, pattern:"build", timeout:60, retry:20 );

  if( "Cisco ACS VERSION INFORMATION" >< show_ver )
  {
    set_kb_item( name:"cisco_acs/show_ver", value:show_ver);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    register_and_report_os( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Cisco Identity Services Engine" >< show_ver )
  {
    set_kb_item( name:"cisco_ise/show_ver", value:show_ver);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    register_and_report_os( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Cisco Prime Collaboration Provisioning" >< show_ver )
  {
    set_kb_item( name:"cisco_pcp/show_ver", value:show_ver);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    register_and_report_os( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Cisco Prime Collaboration Assurance" >< show_ver )
  {
    set_kb_item( name:"cisco_pca/show_ver", value:show_ver);
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    register_and_report_os( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Cisco Prime Infrastructure" >< show_ver )
  {
    set_kb_item( name:"cisco_pis/show_ver", value:show_ver );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/force/pty", value:TRUE );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    register_and_report_os( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if ("Cisco Prime Network Control System" >< show_ver )
  {
    set_kb_item( name:"cisco_ncs/show_ver", value:show_ver );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    set_kb_item( name:"ssh/force/pty", value:TRUE );

    ade_cpe = 'cpe:/o:cisco:application_deployment_engine';
    ade_version = eregmatch( pattern:'ADE-OS Build Version: ([0-9.]+)', string:show_ver );

    if( ! isnull( ade_version[1] ) ) ade_cpe += ':' + ade_version[1];

    register_and_report_os( os:"Cisco Application Deployment Engine OS", cpe:ade_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  exit( 0 );
}

if( ": No such command" >< uname ) {
  system = ssh_cmd( socket:sock, cmd:'status', nosh:TRUE, pty:TRUE, pattern:"Version:\s*FAC" );
  if( system =~ "Version:\s*FAC" && "Architecture" >< system && "Branch point" >< system ) {
    set_kb_item(name:"FortiOS/Authenticator/system", value:system );
    set_kb_item( name:"ssh/force/pty", value:TRUE );
    register_detected_os(os:"FortiOS", oskey:"FortiOS");
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
    exit( 0 );
  }
}

if( "Unknown action 0" >< uname ) {
  system = ssh_cmd( socket:sock, cmd:'get system status', nosh:TRUE );
  if( "Forti" >< system ) {
    set_kb_item(name:"FortiOS/system_status", value:system);
    register_detected_os(os:"FortiOS", oskey:"FortiOS");
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );


    f_version = eregmatch( pattern:"Version\s*:\s*(Forti[^ ]* )?v([0-9.]+)", string:system );
    if( ! isnull( f_version[2] ) )
      set_kb_item( name:"forti/FortiOS/version", value:f_version[2] );

    f_build = eregmatch( string:system, pattern:"[-,]+build([^-, ]+)" );
    if( ! isnull( f_build[1] ) )
      set_kb_item( name:"forti/FortiOS/build", value:f_build[1] );

    f_typ = eregmatch( string:system, pattern: "Platform Full Name\s*:\s*(Forti[^- ]+)");
    if( ! isnull( f_typ[1] ) )
      set_kb_item( name:"forti/FortiOS/typ", value:f_typ[1] );

    exit( 0 );
  }
}

rls = ssh_cmd( socket:sock, cmd:"cat /opt/vmware/etc/appliance-manifest.xml", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/opt/vmware/etc/appliance-manifest.xml: ' + rls + '\n\n';

if( rls =~ "<product>vSphere Data Protection [^<]+</product>" ) {
  set_kb_item( name:"vmware/vSphere_Data_Protection/rls", value:rls );
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/Novell-VA-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/Novell-VA-release: ' + rls + '\n\n';

if( "singleWordProductName=Filr" >< rls ) {
  set_kb_item( name:'filr/ssh/rls', value:rls );
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/vmware/text_top", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/vmware/text_top: ' + rls + '\n\n';

if( "VMware vRealize Log Insight" >< rls ) {
  set_kb_item( name:"vmware/vrealize_log_insight/rls", value:rls );
  exit( 0 );
}

if( "linux" >< tolower( uname ) ) {
  # Cisco MSE 10.x
  mse_status = ssh_cmd( socket:sock, cmd:"cmxctl version", return_errors:FALSE, nosh:TRUE, pty:TRUE );
  if( "Build Version" >< mse_status && "cmx-" >< mse_status && "Build Time" >< mse_status ) {
    set_kb_item( name:"cisco_mse/status", value:mse_status );
    exit( 0 );
  }

  # Cisco MSE <= 8.x
  mse_status = ssh_cmd( socket:sock, cmd:"getserverinfo", return_errors:FALSE, pty:TRUE, timeout:30, retry:10, pattern:"Total Elements" );
  if( "Product name: Cisco Mobility Service Engine" >< mse_status ) {
    set_kb_item( name:"cisco_mse/status", value:mse_status );
    exit( 0 );
  }
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/github/enterprise-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/github/enterprise-release: ' + rls + '\n\n';

if( "RELEASE_VERSION" >< rls && "RELEASE_BUILD_ID" >< rls ) {
  set_kb_item( name:"github/enterprise/rls", value:rls );
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/cisco-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/cisco-release: ' + rls + '\n\n';

if( "Cisco IPICS Enterprise Linux Server" >< rls ) { # Cisco IPICS Enterprise Linux Server release 4.5(1) Build 10p12
  set_kb_item( name:"cisco/ipics/detected", value:TRUE );
  register_and_report_os( os:rls, cpe:"cpe:/o:cisco:linux", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  log_message( port:port, data:string( "We are able to login and detect that you are running ", rls ) );
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/.qradar_install_version", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/.qradar_install_version: ' + rls + '\n\n';

if( rls =~ '^[0-9]\\.[0-9]\\.[0-9]\\.20(1|2)[0-9]+' ) {
  rls = chomp( rls );
  set_kb_item( name:"qradar/version", value:rls );
  typ = ssh_cmd( socket:sock, cmd:"cat /etc/.product_name", return_errors:FALSE );
  if( ! isnull( typ ) ) set_kb_item( name:'qradar/product_name', value:typ );
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/nitrosecurity-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/nitrosecurity-release: ' + rls + '\n\n';

if( "McAfee ETM " >< rls ) {
  buildinfo = ssh_cmd( socket:sock, cmd:"cat /etc/NitroGuard/.buildinfo", return_errors:FALSE );
  if( "VERSION" >< buildinfo && "MAINTVER" >< buildinfo ) {
    set_kb_item( name:"mcafee/etm/buildinfo", value:buildinfo );
    exit( 0 );
  }
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/system-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/system-release: ' + rls + '\n\n';

if( "IPFire" >< rls ) { # IPFire 2.17 (i586) - core91
  set_kb_item( name:"ipfire/system-release", value:rls );
  log_message( port:port, data:string( "We are able to login and detect that you are running ", rls ) );
  register_and_report_os( os:rls, cpe:"cpe:/o:ipfire:linux", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "Amazon Linux AMI release" >< rls ) {
  set_kb_item( name:"ssh/login/amazon_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Amazon Linux" );
  register_detected_os( os:"Amazon Linux", oskey:"AMAZON" );
  exit( 0 );
}

# EON runs on CentOS
if( "EyesOfNetwork release" >< rls ) {

  set_kb_item( name:"eyesofnetwork/ssh/port", value:port );
  set_kb_item( name:"eyesofnetwork/ssh/" + port + "/concludedFile", value:"/etc/system-release" );
  set_kb_item( name:"eyesofnetwork/rls", value:rls );

  set_kb_item( name:"ssh/login/centos", value:TRUE );

  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );

  buf = ssh_cmd( socket:sock, cmd:"cat /etc/system-release-cpe", return_errors:FALSE );

  # EON 4.0 has a wrong cpe:/o:centos:linux in the system-release-cpe
  buf = str_replace( string:buf, find:"centos:linux", replace:"centos:centos" );

  os_ver = eregmatch( pattern:"cpe:/o:centos:centos:([0-9])", string:buf );
  if( ! isnull( os_ver[1] ) ) {
    oskey = "CentOS" + os_ver[1];
    log_message( port:port, data:"We are able to login and detect that you are running CentOS release " + os_ver[1] );
    set_kb_item( name:"ssh/login/release", value:oskey );
    register_and_report_os( os:"CentOS release " + os_ver[1], cpe:buf, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    log_message( port:port, data:"We are able to login and detect that you are running CentOS" );
  }
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/pgp-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/pgp-release: ' + rls + '\n\n';

if( "Symantec Encryption Server" >< rls ) {
  set_kb_item( name:"symantec_encryption_server/installed", value:TRUE );
  set_kb_item( name:"symantec_encryption_server/rls", value:rls );

  mp = ssh_cmd( socket:sock, cmd:"cat /etc/oem-suffix", return_errors:FALSE );
  if( ! isnull( mp ) )
    set_kb_item( name:"symantec_encryption_server/MP", value:chomp( mp ) );

  oem_release = ssh_cmd( socket:sock, cmd:"cat /etc/oem-release", return_errors:FALSE );
  if( ! isnull( oem_release ) )
    set_kb_item( name:"symantec_encryption_server/oem-release", value:chomp( oem_release ) );

  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /VERSION", return_errors:TRUE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/VERSION: ' + rls + '\n\n';

if( "Syntax Error: unexpected argument" >< rls ) {
  rls = ssh_cmd( socket:sock, cmd:'run util bash -c "cat /VERSION"', nosh:TRUE );
  if( "BIG-" >< rls || "Product: EM" >< rls ) {
    set_kb_item( name:"f5/shell_is_tmsh", value:TRUE );
    set_kb_item( name:"ssh/no_linux_shell", value:TRUE );
  }
}

if( "BIG-IP" >< rls ) {
  set_kb_item( name:"f5/big_ip/lsc", value:TRUE ); # gb_f5_big_ip_version.nasl
  set_kb_item( name:"f5/big_ip/VERSION_RAW", value:rls );
  exit( 0 );
}

if( "BIG-IQ" >< rls ) {
  set_kb_item( name:"f5/big_iq/lsc", value:TRUE ); # gb_f5_big_iq_version.nasl
  set_kb_item( name:"f5/big_iq/VERSION_RAW", value:rls );
  exit( 0 );
}

if( "Product: EM" >< rls && "BaseBuild" >< rls ) {
  set_kb_item( name:"f5/f5_enterprise_manager/lsc", value:TRUE ); # gb_f5_enterprise_manager_version.nasl
  set_kb_item( name:"f5/f5_enterprise_manager/VERSION_RAW", value:rls );
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/meg-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/meg-release: ' + rls + '\n\n';

if( rls =~ "^McAfee" ) {
  set_kb_item( name:"mcafee/OS", value:TRUE ); # gb_mcafee_*_version.nasl
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/esrs-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/esrs-release: ' + rls + '\n\n';

if( chomp( rls ) =~ "^[0-9]+\.[0-9]+\.[0-9]$" ) {
  set_kb_item( name:"ems/esrs/rls", value:rls );
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/NAS_CFG/config.xml", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/NAS_CFG/config.xml (truncated): ' + substr( rls, 0, 300 ) + '\n\n';

# <config>
#       *snip*
#       <hw_ver>MyCloudEX2Ultra</hw_ver>
# or:
# <config>
#       *snip*
#       <hw_ver>WDMyCloudMirror</hw_ver>
if( rls =~ "<hw_ver>(WD)?MyCloud.*</hw_ver>" ) {
  set_kb_item( name:"wd-mycloud/ssh-login/" + port + "/cfg_file", value:rls );
  set_kb_item( name:"wd-mycloud/ssh-login/port", value:port );
  set_kb_item( name:"wd-mycloud/ssh-login/cfg_file", value:TRUE );
  exit( 0 );
}

# oraclelinux is almost like rhel .. but ..
rls = ssh_cmd( socket:sock, cmd:"rpm -qf /etc/redhat-release", return_errors:TRUE );

if( "rpm: not found" >!< rls && strlen( rls ) )
  _unknown_os_info += 'rpm -qf /etc/redhat-release: ' + rls + '\n\n';

if( "oraclelinux-release-4" >< rls ) {
  set_kb_item( name:"ssh/login/oracle_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  if( match = eregmatch( pattern:"oraclelinux-release-4.([0-9]+)", string:rls ) ) {
    version = "4." + match[1];
  } else {
    version = "4";
  }
  log_message( port:port, data:"We are able to login and detect that you are running Oracle Linux " + version );
  register_and_report_os( os:"Oracle Linux " + version, cpe:"cpe:/o:oracle:linux:" + version, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  set_kb_item( name:"ssh/login/release", value:"OracleLinux4" ); # nb: Special handling as the Oracle / ELSA LSCs are using just the major release
  exit( 0 );
}

if( "oraclelinux-release-5" >< rls ) {
  set_kb_item( name:"ssh/login/oracle_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  if( match = eregmatch( pattern:"oraclelinux-release-5.([0-9]+)", string:rls ) ) {
    version = "5." + match[1];
  } else {
    version = "5";
  }
  log_message( port:port, data:"We are able to login and detect that you are running Oracle Linux " + version );
  register_and_report_os( os:"Oracle Linux " + version, cpe:"cpe:/o:oracle:linux:" + version, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  set_kb_item( name:"ssh/login/release", value:"OracleLinux5" ); # nb: Special handling as the Oracle / ELSA LSCs are using just the major release
  exit( 0 );
}

if( "oraclelinux-release-6" >< rls ) {
  set_kb_item( name:"ssh/login/oracle_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  if( match = eregmatch( pattern:"oraclelinux-release-6.([0-9]+)", string:rls ) ) {
    version = "6." + match[1];
  } else {
    version = "6";
  }
  log_message( port:port, data:"We are able to login and detect that you are running Oracle Linux " + version );
  register_and_report_os( os:"Oracle Linux " + version, cpe:"cpe:/o:oracle:linux:" + version, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  set_kb_item( name:"ssh/login/release", value:"OracleLinux6" ); # nb: Special handling as the Oracle / ELSA LSCs are using just the major release
  exit( 0 );
}

if( "oraclelinux-release-7" >< rls ) {
  set_kb_item( name:"ssh/login/oracle_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  if( match = eregmatch( pattern:"oraclelinux-release-7.([0-9]+)", string:rls ) ) {
    version = "7." + match[1];
  } else {
    version = "7";
  }
  log_message( port:port, data:"We are able to login and detect that you are running Oracle Linux " + version );
  register_and_report_os( os:"Oracle Linux " + version, cpe:"cpe:/o:oracle:linux:" + version, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  set_kb_item( name:"ssh/login/release", value:"OracleLinux7" ); # nb: Special handling as the Oracle / ELSA LSCs are using just the major release
  exit( 0 );
}

# Ok...let's first check if this is a RedHat/Fedora Core/Mandrake release
rls = ssh_cmd( socket:sock, cmd:"cat /etc/redhat-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/redhat-release: ' + rls + '\n\n';

if( "Space release " >< rls ) {
  set_kb_item( name:"junos/space", value:rls );
  exit( 0 );
}

if( "IWSVA release" >< rls ) {
  system = ssh_cmd( socket:sock, cmd:'/usr/bin/clish -c "show system version"', nosh:TRUE, pty:FALSE );
  if( "Operating System" >< system && "IWSVA" >< system ) {
    set_kb_item( name:"IWSVA/system", value:system);
    exit( 0 );
  }
}

if( "IMSVA release" >< rls ) {
  system = ssh_cmd( socket:sock, cmd:'/usr/bin/clish -c "show module IMSVA version"', nosh:TRUE, pty:FALSE );
  if( system =~ "IMSVA [0-9.]+-Build_Linux_[0-9]+"  ) {
    set_kb_item( name:"IMSVA/system", value:system);
    exit( 0 );
  }
}

if( rls =~ "^XenServer release" ) {
  set_kb_item( name:"xenserver/installed", value:TRUE ); # gb_xenserver_version.nasl
  exit( 0 );
}

if( rls =~ "^McAfee"  ) {
  set_kb_item( name:"mcafee/OS", value:TRUE ); # gb_mcafee_*_version.nasl
  exit( 0 );
}

if( "Red Hat Linux release 7.3" >< rls ) {
  set_kb_item( name:"ssh/login/redhat_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"RH7.3" );
  exit( 0 );
}
if( "Red Hat Linux release 8.0 (Psyche)" >< rls ) {
  set_kb_item( name:"ssh/login/redhat_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"RH8.0" );
  exit( 0 );
}
if( "Red Hat Linux release 9 (Shrike)" >< rls ) {
  set_kb_item( name:"ssh/login/redhat_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"RH9" );
  exit( 0 );
}

if( "Fedora Core release 1 (Yarrow)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora_core", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC1" );
  exit( 0 );
}
if( "Fedora Core release 2 (Tettnang)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora_core", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC2" );
  exit( 0 );
}
if( "Fedora Core release 3 (Heidelberg)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora_core", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC3" );
  exit( 0 );
}
if( "Fedora Core release 4 (Stentz)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora_core", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC4" );
  exit( 0 );
}
if( "Fedora Core release 5 (Bordeaux)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora_core", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC5" );
  exit( 0 );
}
if( "Fedora Core release 6 (Zod)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora_core", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC6" );
  exit( 0 );
}
if( "Fedora release 7 (Moonshine)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC7" );
  exit( 0 );
}
if( "Fedora release 8 (Werewolf)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC8" );
  exit( 0 );
}
if( "Fedora release 9 (Sulphur)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC9" );
  exit( 0 );
}
if( "Fedora release 10 (Cambridge)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC10" );
  exit( 0 );
}
if( "Fedora release 11 (Leonidas)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC11" );
  exit( 0 );
}
if( "Fedora release 12 (Constantine)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC12" );
  exit( 0 );
}
if( "Fedora release 13 (Goddard)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC13" );
  exit( 0 );
}
if( "Fedora release 14 (Laughlin)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC14" );
  exit( 0 );
}
if( "Fedora release 15 (Lovelock)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC15" );
  exit( 0 );
}
if( "Fedora release 16 (Verne)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC16" );
  exit( 0 );
}
if( "Fedora release 17 (Beefy Miracle)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC17" );
  exit( 0 );
}
if( "Fedora release 18 (Spherical Cow)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC18" );
  exit( 0 );
}
if( "Fedora release 19" >< rls && "Cat" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC19" );
  exit( 0 );
}
if( "Fedora release 20" >< rls && "(Heisenbug)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC20" );
  exit( 0 );
}
if( "Fedora release 21" >< rls && "(Twenty One)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC21" );
  exit( 0 );
}
if( "Fedora release 22" >< rls && "(Twenty Two)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC22" );
  exit( 0 );
}
if( "Fedora release 23" >< rls && "(Twenty Three)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC23" );
  exit( 0 );
}
if( "Fedora release 24" >< rls && "(Twenty Four)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC24" );
  exit( 0 );
}
if( "Fedora release 25" >< rls && "(Twenty Five)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC25" );
  exit( 0 );
}
if( "Fedora release 26" >< rls && "(Twenty Six)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC26" );
  exit( 0 );
}
if( "Fedora release 27" >< rls && "(Twenty Seven)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC27" );
  exit( 0 );
}
if( "Fedora release 28" >< rls && "(Twenty Eight)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC28" );
  exit( 0 );
}
if( "Fedora release 29" >< rls && "(Twenty Nine)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC29" );
  exit( 0 );
}
if( "Fedora release 30" >< rls && "(Thirty)" >< rls ) {
  set_kb_item( name:"ssh/login/fedora", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"FC30" );
  exit( 0 );
}

# Red Hat Enterprise Linux ES release 2.1 (Panama)
# Red Hat Enterprise Linux AS release 3 (Taroon Update 1)
# Red Hat Enterprise Linux AS release 3 (Taroon Update 2)
# Red Hat Enterprise Linux AS release 3 (Taroon Update 3)
# Red Hat Enterprise Linux Desktop release 3.90
if( egrep( pattern:"Red Hat Enterprise.*release 2\.1", string:rls ) ) {
  set_kb_item( name:"ssh/login/rhel", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"RHENT_2.1" );
  exit( 0 );
}
if( egrep( pattern:"Red Hat Enterprise.*release 3[ .]", string:rls ) ) {
  set_kb_item( name:"ssh/login/rhel", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"RHENT_3" );
  exit( 0 );
}
if( egrep( pattern:"Red Hat Enterprise.*release 4[ .]", string:rls ) ) {
  set_kb_item( name:"ssh/login/rhel", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"RHENT_4" );
  exit( 0 );
}
if( egrep( pattern:"Red Hat Enterprise.*release 5[ .]", string:rls ) ) {
  set_kb_item( name:"ssh/login/rhel", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"RHENT_5" );
  exit( 0 );
}
if( egrep( pattern:"Red Hat Enterprise.*release 6[ .]", string:rls ) ) {
  set_kb_item( name:"ssh/login/rhel", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"RHENT_6" );
  exit( 0 );
}
if( egrep( pattern:"Red Hat Enterprise.*release 7[ .]", string:rls ) ) {
  set_kb_item( name:"ssh/login/rhel", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"RHENT_7" );
  exit( 0 );
}

if( "Mandriva Linux Enterprise Server release 5.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_mes5" );
  register_detected_os( os:rls, oskey:"MNDK_mes5.0" );
  exit( 0 );
}
if( "Mandriva Linux Enterprise Server release 5.1" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_mes5.1" );
  exit( 0 );
}
if( "Mandriva Linux Enterprise Server release 5.2" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_mes5.2" );
  exit( 0 );
}
if( "Mandriva Linux release 2011.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2011.0" );
  exit( 0 );
}
if( "Mandriva Linux release 2010.2" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2010.2" );
  exit( 0 );
}
if( "Mandriva Linux release 2010.1" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2010.1" );
  exit( 0 );
}
if( "Mandriva Linux release 2010.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2010.0" );
  exit( 0 );
}
if( "Mandriva Linux release 2009.1" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2009.1" );
  exit( 0 );
}
if( "Mandriva Linux release 2009.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2009.0" );
  exit( 0 );
}
if( "Mandriva Linux release 2008.1" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2008.1" );
  exit( 0 );
}
if( "Mandriva Linux release 2008.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2008.0" );
  exit( 0 );
}
if( "Mandriva Linux release 2007.1" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2007.1" );
  exit( 0 );
}
if( "Mandriva Linux release 2007.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2007.0" );
  exit( 0 );
}
if( "Mandriva Linux release 2006.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_2006.0" );
  exit( 0 );
}
if( "Mandrakelinux release 10.1" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_10.1" );
  exit( 0 );
}
if( "Mandrake Linux release 10.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_10.0" );
  exit( 0 );
}
if( "Mandrake Linux release 9.2" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_9.2" );
  exit( 0 );
}
if( "Mandrake Linux release 9.1" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_9.1" );
  exit( 0 );
}
if( "Mandrake Linux release 9.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_9.0" );
  exit( 0 );
}
if( "Mandrake Linux release 8.2" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_8.2" );
  exit( 0 );
}
if( "Mandrake Linux release 8.1" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_8.1" );
  exit( 0 );
}
if( "Mandrake Linux release 8.0" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_8.0" );
  exit( 0 );
}
if( "Mandrake Linux release 7.2" >< rls ) {
  set_kb_item( name:"ssh/login/mandriva_mandrake_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"MNDK_7.2" );
  exit( 0 );
}

if( "Mageia release 6" >< rls ) {
  set_kb_item( name:"ssh/login/mageia_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Mageia release 6" );
  register_detected_os( os:"Mageia release 6", oskey:"MAGEIA6" );
  exit( 0 );
}
if( "Mageia release 5" >< rls ) {
  set_kb_item( name:"ssh/login/mageia_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Mageia release 5" );
  register_detected_os( os:"Mageia release 5", oskey:"MAGEIA5" );
  exit( 0 );
}
if( "Mageia release 4.1" >< rls ) {
  set_kb_item( name:"ssh/login/mageia_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Mageia release 4.1" );
  register_detected_os( os:"Mageia release 4.1", oskey:"MAGEIA4.1" );
  exit( 0 );
}
if( "Mageia release 4" >< rls ) {
  set_kb_item( name:"ssh/login/mageia_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Mageia release 4" );
  register_detected_os( os:"Mageia release 4", oskey:"MAGEIA4" );
  exit( 0 );
}
if( "Mageia release 3" >< rls ) {
  set_kb_item( name:"ssh/login/mageia_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Mageia release 3" );
  register_detected_os( os:"Mageia release 3", oskey:"MAGEIA3" );
  exit( 0 );
}
if( "Mageia release 2" >< rls ) {
  set_kb_item( name:"ssh/login/mageia_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Mageia release 2" );
  register_detected_os( os:"Mageia release 2", oskey:"MAGEIA2" );
  exit( 0 );
}
if( "Mageia release 1" >< rls ) {
  set_kb_item( name:"ssh/login/mageia_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Mageia release 1" );
  register_detected_os( os:"Mageia release 1", oskey:"MAGEIA1" );
  exit( 0 );
}

# Ok...also using /etc/redhat-release is CentOS...let's try them now
# We'll stay with major release # checking unless we find out we need to do
# otherwise.
#CentOS release 4.0 (Final)
#CentOS release 4.1 (Final)
#CentOS release 3.4 (final)

if( "CentOS Linux release 7" >< rls ) {
  set_kb_item( name:"ssh/login/centos", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running CentOS release 7" );
  register_detected_os( os:"CentOS release 7", oskey:"CentOS7" );
  exit( 0 );
}
if( "CentOS release 6" >< rls ) {
  set_kb_item( name:"ssh/login/centos", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running CentOS release 6" );
  register_detected_os( os:"CentOS release 6", oskey:"CentOS6" );
  exit( 0 );
}
if( "CentOS release 5" >< rls ) {
  set_kb_item( name:"ssh/login/centos", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running CentOS release 5" );
  register_detected_os( os:"CentOS release 5", oskey:"CentOS5" );
  exit( 0 );
}
if( "CentOS release 4" >< rls ) {
  set_kb_item( name:"ssh/login/centos", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running CentOS release 4" );
  register_detected_os( os:"CentOS release 4", oskey:"CentOS4" );
  exit( 0 );
}
if( "CentOS release 3" >< rls ) {
  set_kb_item( name:"ssh/login/centos", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running CentOS release 3" );
  register_detected_os( os:"CentOS release 3", oskey:"CentOS3" );
  exit( 0 );
}
if( "CentOS release 2" >< rls ) {
  set_kb_item( name:"ssh/login/centos", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running CentOS release 2" );
  register_detected_os( os:"CentOS release 2", oskey:"CentOS2" );
  exit( 0 );
}

# nb: Keep above the Ubuntu check below so that we're not exiting early without setting the OpenVPN AS infos.
rls = ssh_cmd( socket:sock, cmd:"cat /etc/issue", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/issue: ' + rls + '\n\n';

match = eregmatch( pattern:"^Univention (Managed Client|Mobile Client|DC Master|DC Backup|DC Slave|Memberserver|Corporate Server) ([2][.][0-4])-[0-9]+-[0-9]+", string:rls );
if( ! isnull( match ) ) {
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) {
    register_packages( buf:buf );
    log_message( port:port, data:"We are able to login and detect that you are running " + match[0] );
    register_detected_os( os:"Univention Corporate Server " + match[2], oskey:"UCS" + match[2] );
    exit( 0 );
  }
}

if( "OpenVPN Access Server Appliance" >< rls ) {
  # nb: Used in gb_openvpn_access_server_version.nasl
  set_kb_item( name:"ssh/login/openvpn_as/etc_issue", value:rls );
}

# Hmmm...is it Ubuntu?
rls = ssh_cmd( socket:sock, cmd:"cat /etc/lsb-release", return_errors:FALSE );

#if( "No such file or directory" >!< rls && strlen( rls ) )
#  _unknown_os_info += '/etc/lsb-release: ' + rls;

if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=4.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 4.10" );
  register_detected_os( os:"Ubuntu 4.10", oskey:"UBUNTU4.1" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=5.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 5.04" );
  register_detected_os( os:"Ubuntu 5.04", oskey:"UBUNTU5.04" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=5.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 5.10" );
  register_detected_os( os:"Ubuntu 5.10", oskey:"UBUNTU5.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=6.06" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 6.06" );
  register_detected_os( os:"Ubuntu 6.06", oskey:"UBUNTU6.06 LTS" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=6.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 6.10" );
  register_detected_os( os:"Ubuntu 6.10", oskey:"UBUNTU6.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=7.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 7.04" );
  register_detected_os( os:"Ubuntu 7.04", oskey:"UBUNTU7.04" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=7.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 7.10" );
  register_detected_os( os:"Ubuntu 7.10", oskey:"UBUNTU7.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=8.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 8.04 LTS" );
  register_detected_os( os:"Ubuntu 8.04 LTS", oskey:"UBUNTU8.04 LTS" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=8.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 8.10" );
  register_detected_os( os:"Ubuntu 8.10", oskey:"UBUNTU8.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=9.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 9.04" );
  register_detected_os( os:"Ubuntu 9.04", oskey:"UBUNTU9.04" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=9.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 9.10" );
  register_detected_os( os:"Ubuntu 9.10", oskey:"UBUNTU9.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=10.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 10.04 LTS" );
  register_detected_os( os:"Ubuntu 10.04 LTS", oskey:"UBUNTU10.04 LTS" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=10.10" >< rls) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 10.10" );
  register_detected_os( os:"Ubuntu 10.10", oskey:"UBUNTU10.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=11.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 11.04" );
  register_detected_os( os:"Ubuntu 11.04", oskey:"UBUNTU11.04" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=11.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 11.10" );
  register_detected_os( os:"Ubuntu 11.10", oskey:"UBUNTU11.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=12.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 12.04 LTS" );
  register_detected_os( os:"Ubuntu 12.04 LTS", oskey:"UBUNTU12.04 LTS" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=12.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 12.10" );
  register_detected_os( os:"Ubuntu 12.10", oskey:"UBUNTU12.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=13.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 13.04" );
  register_detected_os( os:"Ubuntu 13.04", oskey:"UBUNTU13.04" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=13.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 13.10" );
  register_detected_os( os:"Ubuntu 13.10", oskey:"UBUNTU13.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=14.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 14.04 LTS" );
  register_detected_os( os:"Ubuntu 14.04 LTS", oskey:"UBUNTU14.04 LTS" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=14.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 14.10" );
  register_detected_os( os:"Ubuntu 14.10", oskey:"UBUNTU14.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=15.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 15.04" );
  register_detected_os( os:"Ubuntu 15.04", oskey:"UBUNTU15.04" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=15.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 15.10" );
  register_detected_os( os:"Ubuntu 15.10", oskey:"UBUNTU15.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=16.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 16.04 LTS" );
  register_detected_os( os:"Ubuntu 16.04 LTS", oskey:"UBUNTU16.04 LTS" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=16.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 16.10" );
  register_detected_os( os:"Ubuntu 16.10", oskey:"UBUNTU16.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=17.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 17.04" );
  register_detected_os( os:"Ubuntu 17.04", oskey:"UBUNTU17.04" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=17.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 17.10" );
  register_detected_os( os:"Ubuntu 17.10", oskey:"UBUNTU17.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=18.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 18.04 LTS" );
  register_detected_os( os:"Ubuntu 18.04 LTS", oskey:"UBUNTU18.04 LTS" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=18.10" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 18.10" );
  register_detected_os( os:"Ubuntu 18.10", oskey:"UBUNTU18.10" );
  exit( 0 );
}
if( "DISTRIB_ID=Ubuntu" >< rls && "DISTRIB_RELEASE=19.04" >< rls ) {
  set_kb_item( name:"ssh/login/ubuntu_linux", value:TRUE );
  ## For Ubuntu19 dpkg -l lists first few lines and user needs to scroll for rest of data
  ## Packages collected in 'buf' variable include only these first few packages.
  ## Currently using dpkg -l|head -10000 to display 10000 lines
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l|head -10000" );
  if( ! isnull( buf ) ) register_packages( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Ubuntu 19.04" );
  register_detected_os( os:"Ubuntu 19.04", oskey:"UBUNTU19.04" );
  exit( 0 );
}

if( rls =~ 'DISTRIB_ID=("|\')?Univention("|\')?' ) {

  ucs_release = eregmatch( string:rls, pattern:'DISTRIB_RELEASE="([1-9][0-9]*[.][0-9]+)-([0-9]+) errata([0-9]+)[^"]*"' );

  if( ! isnull( ucs_release[1] ) ) set_kb_item( name:"ucs/version", value:ucs_release[1] );
  if( ! isnull( ucs_release[2] ) ) set_kb_item( name:"ucs/patch", value:ucs_release[2] );
  if( ! isnull( ucs_release[3] ) ) set_kb_item( name:"ucs/errata", value:ucs_release[3] );

  ucs_description = eregmatch( string:rls, pattern:'DISTRIB_DESCRIPTION="([^"]*)"' );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( ! isnull( buf ) && ! isnull( ucs_release ) && ! isnull( ucs_description ) ) {
    register_packages( buf:buf );
    log_message( port:port, data:"We are able to login and detect that you are running " + ucs_desrciption[1] );
    register_detected_os( os:ucs_description[1], oskey:"UCS" + ucs_release[1] );
    exit( 0 );
  }
}

# How about Conectiva Linux?
rls = ssh_cmd( socket:sock, cmd:"cat /etc/conectiva-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/conectiva-release: ' + rls + '\n\n';

if( "Conectiva Linux 9" >< rls ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Conectiva Linux 9" );
  register_detected_os( os:"Conectiva Linux 9", oskey:"CL9" );
  exit( 0 );
}
if( "Conectiva Linux 10" >< rls ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Conectiva Linux 10" );
  register_detected_os( os:"Conectiva Linux 10", oskey:"CL10" );
  exit( 0 );
}

# How about Turbolinux?
# Turbolinux signatures:
# release 6.0 WorkStation (Shiga)       -- Unsupported
# TurboLinux release 6.1 Server (Naha)  -- Unsupported
# Turbolinux Server 6.5 (Jupiter)       -- Unsupported
# Turbolinux Server 7.0 (Esprit)
# Turbolinux Workstation 7.0 (Monza)
# Turbolinux Server 8.0 (Viper)
# Turbolinux Workstation 8.0 (SilverStone)
# Turbolinux Server 10.0 (Celica)
# Turbolinux Desktop 10.0 (Suzuka)
# -- Need:
#- Turbolinux Appliance Server 1.0 Hosting Edition
#- Turbolinux Appliance Server 1.0 Workgroup Edition
#- Turbolinux Home
#- Turbolinux 10 F...

rls = ssh_cmd( socket:sock, cmd:"cat /etc/turbolinux-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/turbolinux-release: ' + rls + '\n\n';

if( "Turbolinux Server 7.0" >< rls ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"TLS7" );
  exit( 0 );
}
if( "Turbolinux Workstation 7.0" >< rls ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"TLWS7" );
  exit( 0 );
}
if( "Turbolinux Server 8.0" >< rls ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"TLS8" );
  exit( 0 );
}
if( "Turbolinux Workstation 8.0" >< rls ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"TLWS8" );
  exit( 0 );
}
if( "Turbolinux Desktop 10.0" >< rls ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"TLDT10" );
  exit( 0 );
}
if( "Turbolinux Server 10.0" >< rls ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running " + rls );
  register_detected_os( os:rls, oskey:"TLS10" );
  exit( 0 );
}
if( "Turbolinux" >< rls ) {
  log_message( port:port, data:"We have detected you are running a version of Turbolinux currently not supported. Please report the following banner: " + rls );
  exit( 0 );
}

# Hmmm...is it Debian?
rls = ssh_cmd( socket:sock, cmd:"cat /etc/debian_version", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/debian_version: ' + rls + '\n\n';

# nb: At least Ubuntu 18.10 has "buster/sid" in debian_version so keep this in mind
# if Ubuntu is wrongly detected and keep the Ubuntu pattern above the Debian ones.
if( rls =~ "^[0-9]+[0-9.]+" || "buster/sid" >< rls ) {

  rls   = chomp( rls );
  cpe   = "cpe:/o:debian:debian_linux";
  oskey = "DEB";

  set_kb_item( name:"ssh/login/debian_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 dpkg -l" );
  if( buf )
    register_packages( buf:buf );

  log_message( port:port, data:"We are able to login and detect that you are running Debian " + rls );

  vers = eregmatch( pattern:"^([0-9]+)([0-9.]+)", string:rls, icase:FALSE );
  if( vers[1] ) {
    cpe   += ":" + vers[1];
    oskey += vers[1]; # nb: We only want to save the "major" release like 6, 7 and so on in ssh/login/release...
  }

  if( vers[2] ) {
    cpe += vers[2];
    if( vers[1] =~ "^[1-3]$" )
      oskey += "." + vers[2]; # nb: but the older releases needs the second digit as well...
  }

  if( ! vers && "buster/sid" >< rls ) {
    cpe   += ":10.0";
    oskey += "10";
  }

  set_kb_item( name:"ssh/login/release", value:oskey );
  register_and_report_os( os:"Debian GNU/Linux " + rls, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

  exit( 0 );
}

# How about Slackware?
rls = ssh_cmd( socket:sock, cmd:"cat /etc/slackware-version", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/slackware-version: ' + rls + '\n\n';

if( "Slackware 14.2" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 14.2" );
  register_detected_os( os:"Slackware 14.2", oskey:"SLK14.2" );
  exit( 0 );
}
if( "Slackware 14.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 14.1" );
  register_detected_os( os:"Slackware 14.1", oskey:"SLK14.1" );
  exit( 0 );
}
if( "Slackware 14.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 14.0" );
  register_detected_os( os:"Slackware 14.0", oskey:"SLK14.0" );
  exit( 0 );
}
if( "Slackware 13.37" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 13.37" );
  register_detected_os( os:"Slackware 13.37", oskey:"SLK13.37" );
  exit( 0 );
}
if( "Slackware 13.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 13.1" );
  register_detected_os( os:"Slackware 13.1", oskey:"SLK13.1" );
  exit( 0 );
}
if( "Slackware 13.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 13.0" );
  register_detected_os( os:"Slackware 13.0", oskey:"SLK13.0" );
  exit( 0 );
}
if( "Slackware 12.2" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 12.2" );
  register_detected_os( os:"Slackware 12.2", oskey:"SLK12.2" );
  exit( 0 );
}
if( "Slackware 12.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 12.1" );
  register_detected_os( os:"Slackware 12.1", oskey:"SLK12.1" );
  exit( 0 );
}
if( "Slackware 12.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 12.0" );
  register_detected_os( os:"Slackware 12.0", oskey:"SLK12.0" );
  exit( 0 );
}
if( "Slackware 11.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 11.0" );
  register_detected_os( os:"Slackware 11.0", oskey:"SLK11.0" );
  exit( 0 );
}
if( "Slackware 10.2" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 10.2" );
  register_detected_os( os:"Slackware 10.2", oskey:"SLK10.2" );
  exit( 0 );
}
if( "Slackware 10.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 10.1" );
  register_detected_os( os:"Slackware 10.1", oskey:"SLK10.1" );
  exit( 0 );
}
if( "Slackware 10.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 10.0" );
  register_detected_os( os:"Slackware 10.0", oskey:"SLK10.0" );
  exit( 0 );
}
if( "Slackware 9.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 9.1" );
  register_detected_os( os:"Slackware 9.1", oskey:"SLK9.1" );
  exit( 0 );
}
if( "Slackware 9.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 9.0" );
  register_detected_os( os:"Slackware 9.0", oskey:"SLK9.0" );
  exit( 0 );
}
if( "Slackware 8.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 8.1" );
  register_detected_os( os:"Slackware 8.1", oskey:"SLK8.1" );
  exit( 0 );
}
if( "Slackware 8.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 8.0" );
  register_detected_os( os:"Slackware 8.0", oskey:"SLK8.0" );
  exit( 0 );
}
if( "Slackware 7.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 7.1" );
  register_detected_os( os:"Slackware 7.1", oskey:"SLK7.1" );
  exit( 0 );
}
if( "Slackware 7.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 7.0" );
  register_detected_os( os:"Slackware 7.0", oskey:"SLK7.0" );
  exit( 0 );
}
if( "Slackware 4.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 4.0" );
  register_detected_os( os:"Slackware 4.0", oskey:"SLK4.0" );
  exit( 0 );
}
if( "Slackware 3.9" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 3.9" );
  register_detected_os( os:"Slackware 3.9", oskey:"SLK3.9" );
  exit( 0 );
}
if( "Slackware 3.6" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 3.6" );
  register_detected_os( os:"Slackware 3.6", oskey:"SLK3.6" );
  exit( 0 );
}
if( "Slackware 3.5" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 3.5" );
  register_detected_os( os:"Slackware 3.5", oskey:"SLK3.5" );
  exit( 0 );
}
if( "Slackware 3.4" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 3.4" );
  register_detected_os( os:"Slackware 3.4", oskey:"SLK3.4" );
  exit( 0 );
}
if( "Slackware 3.3" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 3.3" );
  register_detected_os( os:"Slackware 3.3", oskey:"SLK3.3" );
  exit( 0 );
}
if( "Slackware 3.2" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 3.2" );
  register_detected_os( os:"Slackware 3.2", oskey:"SLK3.2" );
  exit( 0 );
}
if( "Slackware 3.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 3.1" );
  register_detected_os( os:"Slackware 3.1", oskey:"SLK3.1" );
  exit( 0 );
}
if( "Slackware 3.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 3.0" );
  register_detected_os( os:"Slackware 3.0", oskey:"SLK3.0" );
  exit( 0 );
}
if( "Slackware 2.3" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 2.3" );
  register_detected_os( os:"Slackware 2.3", oskey:"SLK2.3" );
  exit( 0 );
}
if( "Slackware 2.2" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 2.2" );
  register_detected_os( os:"Slackware 2.2", oskey:"SLK2.2" );
  exit( 0 );
}
if( "Slackware 2.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 2.1" );
  register_detected_os( os:"Slackware 2.1", oskey:"SLK2.1" );
  exit( 0 );
}
if( "Slackware 2.0" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 2.0" );
  register_detected_os( os:"Slackware 2.0", oskey:"SLK2.0" );
  exit( 0 );
}
if( "Slackware 1.1" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 1.1" );
  register_detected_os( os:"Slackware 1.1", oskey:"SLK1.1" );
  exit( 0 );
}
if( "Slackware 1.00" >< rls ) {
  set_kb_item( name:"ssh/login/slackware_linux", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"ls /var/log/packages" );
  set_kb_item( name:"ssh/login/slackpack", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Slackware 1.00" );
  register_detected_os( os:"Slackware 1.00", oskey:"SLK1.00" );
  exit( 0 );
}

# How about SuSe? and openSUSE?
# https://en.wikipedia.org/wiki/SUSE_Linux_distributions
rls = ssh_cmd( socket:sock, cmd:"cat /etc/os-release", return_errors:FALSE );

# if( "No such file or directory" >!< rls && strlen( rls ) )
#  _unknown_os_info += '/etc/os-release: ' + rls;

if( "openSUSE Leap 15.0" >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE Leap 15.0" );
  register_detected_os( os:"openSUSE Leap 15.0", oskey:"openSUSELeap15.0" );
  exit( 0 );
}
if( "openSUSE Leap 42.3" >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE Leap 42.3" );
  register_detected_os( os:"openSUSE Leap 42.3", oskey:"openSUSELeap42.3" );
  exit( 0 );
}
if( "openSUSE Leap 42.2" >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE Leap 42.2" );
  register_detected_os(os:"openSUSE Leap 42.2", oskey:"openSUSELeap42.2" );
  exit( 0 );
}
if( "openSUSE Leap 42.1" >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE Leap 42.1" );
  register_detected_os( os:"openSUSE Leap 42.1", oskey:"openSUSELeap42.1" );
  exit( 0 );
}
if( "openSUSE Leap 42.0" >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE Leap 42.0" );
  register_detected_os( os:"openSUSE Leap 42.0", oskey:"openSUSELeap42.0" );
  exit( 0 );
}

# nb: Arch Linux is a rolling release so there is no "real" version
if( 'NAME="Arch Linux"' >< rls ) {
  set_kb_item( name:"ssh/login/arch_linux", value:TRUE );
  log_message( port:port, data:"We are able to login and detect that you are running Arch Linux. Note: Local Security Checks (LSC) are not available for this OS." );
  register_detected_os( os:"Arch Linux", oskey:"ArchLinux" );
  exit( 0 );
}

if( "NAME=NixOS" >< rls || "ID=nixos" >< rls ) {
  set_kb_item( name:"ssh/login/nixos", value:TRUE );
  # e.g. VERSION_ID="18.09pre145524.2a8a5533d18"
  version = eregmatch( pattern:'VERSION_ID="([^"]+)"', string:rls );
  if( version[1] ) {
    log_message( port:port, data:"We are able to login and detect that you are running NixOS " + version[1] + ". Note: Local Security Checks (LSC) are not available for this OS." );
    register_and_report_os( os:"NixOS", version:version[1], cpe:"cpe:/o:nixos_project:nixos", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    log_message( port:port, data:"We are able to login and detect that you are running an unknown NixOS release. Note: Local Security Checks (LSC) are not available for this OS." );
    register_and_report_os( os:"NixOS", cpe:"cpe:/o:nixos_project:nixos", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    register_unknown_os_banner( banner:'Unknown NixOS release.\n\ncat /etc/os-release: ' + rls, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }
  exit( 0 );
}

# nb: In SLES12+ /etc/SuSE-release is deprecated in favor of /etc/os-release
rls = ssh_cmd( socket:sock, cmd:"cat /etc/SuSE-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/SuSE-release: ' + rls + '\n\n';

if( match = eregmatch( pattern:"SUSE Linux Enterprise Desktop ([0-9]+)", string:rls ) ) {

  patchlevel = eregmatch( pattern:"PATCHLEVEL = ([0-9]+)", string:rls );
  if( ! patchlevel ) patchlevel[1] = "0";

  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SUSE Linux Enterprise Desktop " + match[1] + " SP" + patchlevel[1] );
  register_detected_os( os:"SUSE Linux Enterprise Desktop " + match[1] + " SP" + patchlevel[1], oskey:"SLED" + match[1] + ".0SP" + patchlevel[1] );
  exit( 0 );
}

# nb: LSCs for SLES 10 and below used the oskey without the SP so keep this above newer releases
if( "SUSE Linux Enterprise Server 10 " >< rls ) {
  set_kb_item( name:"ssh/login/suse_sles", value:TRUE ); # For a few older LSCs
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SUSE Linux Enterprise Server 10" );
  register_detected_os( os:"SUSE Linux Enterprise Server 10", oskey:"SLES10.0" );
  exit( 0 );
}
if( "SUSE LINUX Enterprise Server 9 " >< rls ) {
  set_kb_item( name:"ssh/login/suse_sles", value:TRUE ); # For a few older LSCs
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SUSE Linux Enterprise Server 9" );
  register_detected_os( os:"SUSE Linux Enterprise Server 9", oskey:"SLES9.0" );
  exit( 0 );
}
# nb: Same for SLES 11 SP0. LSCs also only used SLES11.0
if( "SUSE Linux Enterprise Server 11 " >< rls && "PATCHLEVEL = 0" >< rls ) {
  set_kb_item( name:"ssh/login/suse_sles", value:TRUE ); # For a few older LSCs
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SUSE Linux Enterprise Server 11" );
  register_detected_os( os:"SUSE Linux Enterprise Server 11", oskey:"SLES11.0" );
  exit( 0 );
}
# For all other SLES releases...
# e.g. SUSE Linux Enterprise Server 11 (x86_64)
if( match = eregmatch( pattern:"SUSE Linux Enterprise Server ([0-9]+)", string:rls ) ) {

  patchlevel = eregmatch( pattern:"PATCHLEVEL = ([0-9]+)", string:rls );
  if( ! patchlevel ) patchlevel[1] = "0";

  set_kb_item( name:"ssh/login/suse_sles", value:TRUE ); # For a few older LSCs
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SUSE Linux Enterprise Server " + match[1] + " SP" + patchlevel[1] );
  register_detected_os( os:"SUSE Linux Enterprise Server " + match[1] + " SP" + patchlevel[1], oskey:"SLES" + match[1] + ".0SP" + patchlevel[1] );
  exit( 0 );
}

if( "openSUSE 13.2 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 13.2" );
  register_detected_os( os:"openSUSE 13.2", oskey:"openSUSE13.2" );
  exit( 0 );
}
if( "openSUSE 13.1 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 13.1" );
  register_detected_os( os:"openSUSE 13.1", oskey:"openSUSE13.1" );
  exit( 0 );
}
if( "openSUSE 12.3 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 12.3" );
  register_detected_os( os:"openSUSE 12.3", oskey:"openSUSE12.3" );
  exit( 0 );
}
if( "openSUSE 12.2 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 12.2" );
  register_detected_os( os:"openSUSE 12.2", oskey:"openSUSE12.2" );
  exit( 0 );
}
if( "openSUSE 12.1 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 12.1" );
  register_detected_os( os:"openSUSE 12.1", oskey:"openSUSE12.1" );
  exit( 0 );
}
if( "openSUSE 11.4 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 11.4" );
  register_detected_os( os:"openSUSE 11.4", oskey:"openSUSE11.4" );
  exit( 0 );
}
if( "openSUSE 11.3 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 11.3" );
  register_detected_os( os:"openSUSE 11.3", oskey:"openSUSE11.3" );
  exit( 0 );
}
if( "openSUSE 11.2 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 11.2" );
  register_detected_os( os:"openSUSE 11.2", oskey:"openSUSE11.2" );
  exit( 0 );
}
if( "openSUSE 11.1 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 11.1" );
  register_detected_os( os:"openSUSE 11.1", oskey:"openSUSE11.1" );
  exit( 0 );
}
if( "openSUSE 11.0 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 11.0" );
  register_detected_os( os:"openSUSE 11.0", oskey:"openSUSE11.0" );
  exit( 0 );
}
if( "openSUSE 10.3 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 10.3" );
  register_detected_os( os:"openSUSE 10.3", oskey:"openSUSE10.3" );
  exit( 0 );
}
if( "openSUSE 10.2 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running openSUSE 10.2" );
  register_detected_os( os:"openSUSE 10.2", oskey:"openSUSE10.2" );
  exit( 0 );
}
if( "SUSE LINUX 10.1 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 10.1" );
  register_detected_os( os:"SuSE Linux 10.1", oskey:"SUSE10.1" );
  exit( 0 );
}
if( "SUSE LINUX 10.0 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 10.0" );
  register_detected_os( os:"SuSE Linux 10.0", oskey:"SUSE10.0" );
  exit( 0 );
}
if( "SuSE Linux 9.3 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 9.3" );
  register_detected_os( os:"SuSE Linux 9.3", oskey:"SUSE9.3" );
  exit( 0 );
}
if( "SuSE Linux 9.2 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 9.2" );
  register_detected_os( os:"SuSE Linux 9.2", oskey:"SUSE9.2" );
  exit( 0 );
}
if( "SuSE Linux 9.1 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 9.1" );
  register_detected_os( os:"SuSE Linux 9.1", oskey:"SUSE9.1" );
  exit( 0 );
}
if( "SuSE Linux 9.0 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 9.0" );
  register_detected_os( os:"SuSE Linux 9.0", oskey:"SUSE9.0" );
  exit( 0 );
}
if( "SuSE Linux 8.2 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 8.2" );
  register_detected_os( os:"SuSE Linux 8.2", oskey:"SUSE8.2" );
  exit( 0 );
}
if( "SuSE Linux 8.1 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 8.1" );
  register_detected_os( os:"SuSE Linux 8.1", oskey:"SUSE8.1" );
  exit( 0 );
}
if( "SuSE Linux 8.0 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 8.0" );
  register_detected_os( os:"SuSE Linux 8.0", oskey:"SUSE8.0" );
  exit( 0 );
}
if( "SuSE Linux 7.3 " >< rls ) {
  set_kb_item( name:"ssh/login/suse", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running SuSE Linux 7.3" );
  register_detected_os( os:"SuSE Linux 7.3", oskey:"SUSE7.3" );
  exit( 0 );
}

rls = ssh_cmd( socket:sock, cmd:"cat /etc/release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/release: ' + rls + '\n\n';

if( "Endian Firewall " >< rls ) {
  set_kb_item( name:"endian_firewall/release", value:rls );
  exit( 0 );
}

# How about Trustix?
rls2 = ssh_cmd( socket:sock, cmd:"cat /etc/trustix-release", return_errors:FALSE );

if( "No such file or directory" >!< rls2 && strlen( rls2 ) )
  _unknown_os_info += '/etc/trustix-release: ' + rls2 + '\n\n';

if( "Trustix Secure Linux release 3.0.5" >< rls ||
    "Trustix Secure Linux release 3.0.5" >< rls2 ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Trustix 3.0.5" );
  register_detected_os( os:"Trustix 3.0.5", oskey:"TSL3.0.5" );
  exit( 0 );
}
if( "Trustix Secure Linux release 3.0" >< rls ||
    "Trustix Secure Linux release 3.0" >< rls2 ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Trustix 3.0" );
  register_detected_os( os:"Trustix 3.0", oskey:"TSL3.0" );
  exit( 0 );
}
if( "Trustix Secure Linux release 2.2" >< rls ||
    "Trustix Secure Linux release 2.2" >< rls2 ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Trustix 2.2" );
  register_detected_os( os:"Trustix 2.2", oskey:"TSL2.2" );
  exit( 0 );
}
if( "Trustix Secure Linux release 2.1" >< rls ||
    "Trustix Secure Linux release 2.1" >< rls2 ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Trustix 2.1" );
  register_detected_os( os:"Trustix 2.1", oskey:"TSL2.1" );
  exit( 0 );
}
if( "Trustix Secure Linux release 2.0" >< rls ||
    "Trustix Secure Linux release 2.0" >< rls2 ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Trustix 2.0" );
  register_detected_os( os:"Trustix 2.0", oskey:"TSL2.0" );
  exit( 0 );
}
if("Trustix Secure Linux release 1.5"><rls ||
    "Trustix Secure Linux release 1.5"><rls2) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Trustix 1.5" );
  register_detected_os( os:"Trustix 1.5", oskey:"TSL1.5" );
  exit( 0 );
}
if( "Trustix Secure Linux release 1.2" >< rls ||
    "Trustix Secure Linux release 1.2" >< rls2) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Trustix 1.2" );
  register_detected_os( os:"Trustix 1.2", oskey:"TSL1.2" );
  exit( 0 );
}
if( "Trustix Secure Linux release 1.1" >< rls ||
    "Trustix Secure Linux release 1.1" >< rls2 ) {
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'" );
  register_rpms( buf:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Trustix 1.1" );
  register_detected_os( os:"Trustix 1.1", oskey:"TSL1.1" );
  exit( 0 );
}
# Missing Trustix e-2

# How about Gentoo? Note, just check that its ANY gentoo release, since the build
# doesn't matter for purposes of checking package version numbers.
rls = ssh_cmd( socket:sock, cmd:"cat /etc/gentoo-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/gentoo-release: ' + rls + '\n\n';

if( "Gentoo" >< rls ) {
  set_kb_item( name:"ssh/login/gentoo", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:'find /var/db/pkg -mindepth 2 -maxdepth 2 -printf "%P\\n"' );
  set_kb_item( name:"ssh/login/pkg", value:buf );
  # Determine the list of maintained packages
  buf = ssh_cmd( socket:sock, cmd:"find /usr/portage/ -wholename '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\([^/]*\)/.*/\([^/]*\)\.ebuild$,\1/\2,'" );
  if( strlen( buf ) == 0 ) { # Earlier find used 'path' in place of 'wholename'
    buf = ssh_cmd( socket:sock, cmd:"find /usr/portage/ -path '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\([^/]*\)/.*/\([^/]*\)\.ebuild$,\1/\2,'" );
  }
  set_kb_item( name:"ssh/login/gentoo_maintained", value:buf );
  log_message( port:port, data:"We are able to login and detect that you are running Gentoo" );
  register_detected_os( os:"Gentoo", oskey:"GENTOO" );
  exit( 0 );
}

# EulerOS
# nb: Sometimes there seems to be inconsistencies in the output, this was seen on a 2.0 SP0 (without SP) installation:
# cat /etc/redhat-release: EulerOS release 2.0
# rpm -qf /etc/redhat-release: euleros-release-2.0SP2-6.x86_64
# cat /etc/euleros-release: EulerOS release 2.0
#
rls = ssh_cmd( socket:sock, cmd:"cat /etc/euleros-release", return_errors:FALSE );

if( "No such file or directory" >!< rls && strlen( rls ) )
  _unknown_os_info += '/etc/euleros-release: ' + rls + '\n\n';

# EulerOS release 2.0
# EulerOS release 2.0 (SP2)
if( rls =~ "EulerOS release" ) {

  rls   = chomp( rls );
  cpe   = "cpe:/o:huawei:euleros";
  oskey = "EULEROS";

  set_kb_item( name:"ssh/login/euleros", value:TRUE );
  buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  register_rpms( buf:buf );

  log_message( port:port, data:"We are able to login and detect that you are running " + rls );

  vers_nd_sp = eregmatch( pattern:"^EulerOS release ([0-9]+\.[0-9]+)( \(SP([0-9]+)\))?", string:rls, icase:TRUE );
  if( vers_nd_sp[1] ) {

    cpe   += ":" + vers_nd_sp[1];
    oskey += vers_nd_sp[1];

    if( vers_nd_sp[3] ) {
      cpe   += ":sp" + vers_nd_sp[3];
      oskey += "SP" + vers_nd_sp[3];
    } else {
      oskey += "SP0";
    }
  }

  set_kb_item( name:"ssh/login/release", value:oskey );
  register_and_report_os( os:rls, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );

  exit( 0 );
}

# Non GNU/Linux platforms:

## HP-UX Operating System
if( "HP-UX" >< uname ) {

  rls = ssh_cmd( socket:sock, cmd:"uname -r" );

  if( "10.01" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 10.01" );
    register_detected_os( os:"HP-UX 10.01", oskey:"HPUX10.01" );
    exit( 0 );
  }
  if( "10.10" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 10.10" );
    register_detected_os( os:"HP-UX 10.10", oskey:"HPUX10.10" );
    exit( 0 );
  }
  if( "10.20" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 10.20" );
    register_detected_os( os:"HP-UX 10.20", oskey:"HPUX10.20" );
    exit( 0 );
  }
  if( "10.24" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 10.24" );
    register_detected_os( os:"HP-UX 10.24", oskey:"HPUX10.24" );
    exit( 0 );
  }
  if( "10.26" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 10.26" );
    register_detected_os( os:"HP-UX 10.26", oskey:"HPUX10.26" );
    exit( 0 );
  }
  if( "11.00" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 11.00" );
    register_detected_os( os:"HP-UX 11.00", oskey:"HPUX11.00" );
    exit( 0 );
  }
  if( "11.04" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 11.04" );
    register_detected_os( os:"HP-UX 11.04", oskey:"HPUX11.04" );
    exit( 0 );
  }
  if( "11.10" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 11.10" );
    register_detected_os( os:"HP-UX 11.10", oskey:"HPUX11.10" );
    exit( 0 );
  }
  if( "11.11" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 11.11" );
    register_detected_os( os:"HP-UX 11.11", oskey:"HPUX11.11" );
    exit( 0 );
  }
  if( "11.20" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 11.20" );
    register_detected_os( os:"HP-UX 11.20", oskey:"HPUX11.20" );
    exit( 0 );
  }
  if( "11.22" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 11.22" );
    register_detected_os( os:"HP-UX 11.22", oskey:"HPUX11.22" );
    exit( 0 );
  }
  if( "11.23" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 11.23" );
    register_detected_os( os:"HP-UX 11.23", oskey:"HPUX11.23" );
    exit( 0 );
  }
  if( "11.31" >< rls ) {
    set_kb_item( name:"ssh/login/hp_hp-ux", value:TRUE );
    buf = ssh_cmd( socket:sock, cmd:"swlist -l patch -a supersedes" );
    set_kb_item( name:"ssh/login/hp_pkgsupersedes", value:buf );
    buf = ssh_cmd( socket:sock, cmd:"swlist -a revision -l fileset" );
    set_kb_item( name:"ssh/login/hp_pkgrev", value:buf );
    log_message( port:port, data:"We are able to login and detect that you are running HP-UX 11.31" );
    register_detected_os( os:"HP-UX 11.31", oskey:"HPUX11.31" );
    exit( 0 );
  }
}

#How about FreeBSD?  If the uname line begins with "FreeBSD ", we have a match
#We need to run uname twice, because of lastlogin and motd ..
# nb: pfSense is also running on FreeBSD, see for a special handling for this at the top
uname = ssh_cmd( socket:sock, cmd:"uname -a" );
if( "FreeBSD" >< uname ) {

  set_kb_item( name:"ssh/login/freebsd", value:TRUE );

  register_uname( uname:uname );

  osversion = ssh_cmd( socket:sock, cmd:"uname -r" );

  version = eregmatch( pattern:"^[^ ]+ [^ ]+ ([^ ]+)+", string:uname );
  splitup = eregmatch( pattern:"([^-]+)-([^-]+)-p([0-9]+)", string:version[1] );
  found = 0;
  if( ! isnull( splitup ) ) {
    release    = splitup[1];
    patchlevel = splitup[3];
    found = 1;
  } else {
    splitup = eregmatch( pattern:"([^-]+)-RELEASE", string:version[1] );
    if( ! isnull( splitup ) ) {
      release    = splitup[1];
      patchlevel = "0";
      found = 1;
    } else {
      splitup = eregmatch( pattern:"([^-]+)-SECURITY",string:version[1] );
      if( ! isnull( splitup ) ) {
        release = splitup[1];
        log_message( port:port, data:"We have detected you are running FreeBSD " + splitup[0] + ". It also appears that you are using freebsd-update, a binary update tool for keeping your distribution up to date. We will not be able to check your core distribution for vulnerabilities, but we will check your installed ports packages." );
        found = 2;
      } else {
        log_message( port:port, data:"You appear to be running FreeBSD, but we do not recognize the output format of uname: " + uname + ". Local security checks will NOT be run." );
        register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
        # nb: We want to report the unknown / not detected version
        register_unknown_os_banner( banner:'Unknown FreeBSD release.\n\nuname -a: ' + uname + '\nuname -r: ' + osversion, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
      }
    }
  }
  if( found == 1 ) {
    set_kb_item( name:"ssh/login/freebsdrel", value:release );
    set_kb_item( name:"ssh/login/freebsdpatchlevel", value:patchlevel );
    register_and_report_os( os:"FreeBSD", version:release, cpe:"cpe:/o:freebsd:freebsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    log_message( port:port, data:"We are able to login and detect that you are running FreeBSD " + release + " Patch level: " + patchlevel );
  }
  if( found == 2 ) {
    set_kb_item( name:"ssh/login/freebsdrel", value:release );
    register_and_report_os( os:"FreeBSD", version:release, cpe:"cpe:/o:freebsd:freebsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    log_message( port:port, data:"We are able to login and detect that you are running FreeBSD " + release + " Patch level: Unknown" );
  }
  if( found != 0 ) {
    buf = ssh_cmd( socket:sock, cmd:"pkg info" );
    set_kb_item( name:"ssh/login/freebsdpkg", value:buf );
  }
  exit( 0 );
}

# Whilst we're at it, lets check if it's Solaris
if( "SunOS " >< uname ) {

  set_kb_item( name:"ssh/login/solaris", value:TRUE );

  register_uname( uname:uname );

  osversion = ssh_cmd( socket:sock, cmd:"uname -r" );
  set_kb_item( name:"ssh/login/solosversion", value:osversion );

  if( match = eregmatch( pattern:"^([0-9.]+)", string:osversion ) ) {
    register_and_report_os( os:"Solaris", version:match[1], cpe:"cpe:/o:sun:solaris", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Solaris", cpe:"cpe:/o:sun:solaris", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    # nb: We want to report the unknown / not detected version
    register_unknown_os_banner( banner:'Unknown Solaris release.\n\nuname: ' + uname + '\nuname -r: ' + osversion, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }

  hardwaretype = ssh_cmd( socket:sock, cmd:"uname -p" );
  set_kb_item( name:"ssh/login/solhardwaretype", value:hardwaretype );
  if( hardwaretype >< "sparc" ) {
    log_message( port:port, data:"We are able to login and detect that you are running Solaris " + osversion + " Arch: SPARC" );
  } else {
    log_message( port:port, data:"We are able to login and detect that you are running Solaris " + osversion + " Arch: x86" );
  }

  buf = ssh_cmd( socket:sock, cmd:"pkginfo" );
  set_kb_item( name:"ssh/login/solpackages", value:buf );

  buf = ssh_cmd( socket:sock, cmd:"showrev -p" );
  set_kb_item( name:"ssh/login/solpatches", value:buf );

  exit( 0 );
}

# This is just doing a basic detection, we don't have any LSCs for OpenBSD...
# OpenBSD $hostname 5.5 GENERIC#271 amd64
# OpenBSD $hostname 6.3 GENERIC#100 amd64
if( "OpenBSD " >< uname ) {

  set_kb_item( name:"ssh/login/openbsd", value:TRUE );

  register_uname( uname:uname );

  osversion = ssh_cmd( socket:sock, cmd:"uname -r" );
  set_kb_item( name:"ssh/login/openbsdversion", value:osversion );

  if( match = eregmatch( pattern:"^([0-9.]+)", string:osversion ) ) {
    register_and_report_os( os:"OpenBSD", version:match[1], cpe:"cpe:/o:openbsd:openbsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    # nb: We want to report the unknown / not detected version
    register_unknown_os_banner( banner:'Unknown OpenBSD release.\n\nuname: ' + uname + '\nuname -r: ' + osversion, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }
  exit( 0 );
}

#maybe it's a real OS... like Mac OS X :)
if( "Darwin" >< uname ) {

  register_uname( uname:uname );

  sw_vers_buf = ssh_cmd( socket:sock, cmd:"sw_vers" );
  log_message( data:'We are able to login and detect that you are running:\n' + sw_vers_buf );

  buf = chomp( ssh_cmd( socket:sock, cmd:"sw_vers -productName" ) );
  set_kb_item( name:"ssh/login/osx_name", value:buf );

  buf = chomp( ssh_cmd( socket:sock, cmd:"sw_vers -productVersion" ) );
  if( match = eregmatch( pattern:"^([0-9]+\.[0-9]+\.[0-9]+)", string:buf ) )
  {
    set_kb_item( name:"ssh/login/osx_version", value:match[1]);
    register_and_report_os( os:"Mac OS X / macOS", version:match[1], cpe:"cpe:/o:apple:mac_os_x", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Mac OS X / macOS", cpe:"cpe:/o:apple:mac_os_x", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    # nb: We want to report the unknown / not detected version
    register_unknown_os_banner( banner:'Unknown Mac OS X  / macOS release.\n\nsw_vers output:\n' + sw_vers_buf, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  }

  buf = chomp( ssh_cmd( socket:sock, cmd:"sw_vers -buildVersion" ) );
  set_kb_item( name:"ssh/login/osx_build", value:buf );

  buf = ssh_cmd( socket:sock, cmd:"list=$(pkgutil --pkgs);for l in $list;do echo $l;v=$(pkgutil --pkg-info $l | grep version);echo ${v#version: };done;" );
  set_kb_item( name:"ssh/login/osx_pkgs", value:buf );

  exit( 0 );
}

# Minix 127.0.0.1 3.3.0 Minix 3.3.0 (GENERIC) i386
# nb: Keep down below to only catch the "uname -a" from FreeBSD above which doesn't
# contain the full PTY output / banner of Minix.
if( uname =~ "^Minix " ) {

  register_uname( uname:uname );

  set_kb_item( name:"ssh/login/minix", value:TRUE );

  # e.g.:
  # openssh-6.6.1        Open Source Secure shell client and server (remote login program)
  # openssl-1.0.1g       Secure Socket Layer and cryptographic library
  buf = chomp( ssh_cmd( socket:sock, cmd:"pkgin list" ) );
  set_kb_item( name:"ssh/login/pkgin_pkgs", value:buf );

  minix_cpe = "cpe:/o:minix3:minix";
  minix_version = eregmatch( pattern:"^Minix .* Minix ([0-9.]+) ", string:uname );
  report = "We are able to login and detect that you are running MINIX3";

  if( ! isnull( minix_version[1] ) ) {
    report += " " + minix_version[1];
    register_and_report_os( os:"MINIX3", version:minix_version[1], cpe:minix_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"MINIX3", cpe:minix_cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  log_message( data:report + ". Note: Local Security Checks (LSC) are not available for this OS." );
  exit( 0 );
}

# TODO:
#{ "NetBSD",     "????????????????",         },
#{ "WhiteBox",   "????????????????",         },
#{ "Linspire",   "????????????????",         },
#{ "Desktop BSD","????????????????",         },
#{ "PC-BSD",     "????????????????",         },
#{ "FreeSBIE",   "????????????????",         },
#{ "JDS",        "/etc/sun-release",         },
#{ "Yellow Dog", "/etc/yellowdog-release",   },

if( uname ) {
  _unknown_os_info = 'uname: ' + uname + '\n\n' + _unknown_os_info;
  report  = 'System identifier unknown:\n\n';
  report += uname;
  report += '\n\nTherefore no local security checks applied (missing list of installed packages) ';
  report += 'though SSH login provided and works.';
} else {
  report  = 'System identifier unknown. Therefore no local security checks applied ';
  report += '(missing list of installed packages) though SSH login provided and works.';
}

if( _unknown_os_info ) {
  register_unknown_os_banner( banner:_unknown_os_info, banner_type_name:SCRIPT_DESC, banner_type_short:"gather_package_list", port:port );
  report += '\n\n' + "Please see the VT 'Unknown OS and Service Banner Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108441) ";
  report += "for possible ways to identify this OS.";
}

log_message( port:port, data:report );

exit( 0 );
