###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dns_os_detection.nasl 14076 2019-03-10 17:26:11Z cfischer $
#
# DNS Server OS Identification
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108014");
  script_version("$Revision: 14076 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-10 18:26:11 +0100 (Sun, 10 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-03 14:13:48 +0100 (Thu, 03 Nov 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DNS Server OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_dependencies("dns_server.nasl");
  script_mandatory_keys("DNS/identified");

  script_tag(name:"summary", value:"This script performs DNS banner based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

SCRIPT_DESC = "DNS Server OS Identification";
BANNER_TYPE = "DNS server banner";

foreach proto( make_list( "udp", "tcp" ) ) {

  banners = get_kb_list( "DNS/" + proto + "/version_request/*" );
  if( isnull( banners ) ) continue;

  foreach key( keys( banners ) ) {

    kb_key = "DNS/" + proto + "/version_request/";
    port   = int( key - kb_key );
    banner = banners[key];

    if( "Microsoft" >< banner || "Windows" >< banner ) {
      if( "Windows 2008 DNS Server Ready" >< banner ) {
        register_and_report_os( os:"Microsoft Windows 2008 Server", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      } else {
        register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      }
      continue;
    }

    if( "FreeBSD" >< banner ) {
      register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "SunOS DNS Server" >< banner ) {
      register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "Gentoo Gnu/Linux" >< banner ) {
      register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "-Ubuntu" >< banner ) {
      register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # PowerDNS Authoritative Server 3.4.11 (jenkins@autotest.powerdns.com built 20170116223245 mockbuild@buildhw-05.phx2.fedoraproject.org)
    if( "for Fedora Linux" >< banner || ( ( "PowerDNS" >< banner || "jenkins@autotest.powerdns.com" >< banner ) && ".fedoraproject.org" >< banner ) ) {
      register_and_report_os( os:"Fedora Linux", cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "-SuSE" >< banner ) {
      register_and_report_os( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "-RedHat" >< banner && ".fc" >< banner ) {
      version = eregmatch( pattern:"\.fc([0-9]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Fedora Linux", version:version[1], cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Fedora Linux", cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # 9.9.4-RedHat-9.9.4-50.1.h2
    if( banner =~ "-RedHat.+\.h" ) {
      version = eregmatch( pattern:"[0-9.-]+\.h([1-9])", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"EulerOS", version:version[1], cpe:"cpe:/o:huawei:euleros", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"EulerOS", cpe:"cpe:/o:huawei:euleros", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "-RedHat" >< banner ) {
      version = eregmatch( pattern:"\.el([0-9]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Redhat Linux", version:version[1], cpe:"cpe:/o:redhat:linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # PowerDNS" "Authoritative" "Server" "3.4.11" "(jenkins@autotest.powerdns.com" "built" "20171130121213" "root@rpmb-64-centos-65)
    # PowerDNS" "Authoritative" "Server" "3.4.10" "(jenkins@autotest.powerdns.com" "built" "20170306160718" "root@rpmbuild-64-centos-7.dev.cpanel.net)
    if( ( "PowerDNS" >< banner || "jenkins@autotest.powerdns.com" >< banner ) && "-centos-" >< banner ) {
      if( "-centos-7" >< banner ) {
        register_and_report_os( os:"CentOS", version:"7", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "-centos-65" >< banner ) {
        register_and_report_os( os:"CentOS", version:"6.5", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "-Debian" >< banner || ( "PowerDNS Authoritative Server" >< banner && "debian.org)" >< banner ) ) {
      if( "+deb8" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "9.10.3-P4-Debian" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # Those are only running on Unix-like OS variantes
    # keep at the bottom so the pattern above are evaluated first.
    # dnsmasq-pi-hole-2.79
    # dnsmasq-2.76
    if( banner =~ "^dnsmasq" || banner =~ "^PowerDNS Authoritative Server" || banner =~ "^PowerDNS Recursor" || "jenkins@autotest.powerdns.com" >< banner || banner =~ "^Knot DNS" ) {
      # Doesn't have any OS info so just reqister Linux/Unix
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      # Only continue here for the pattern without OS info so we register an unknown OS down below if there is any additional data in the banner we want to know
      if( banner == "dnsmasq" || egrep( pattern:"^dnsmasq-(pi-hole-)?([0-9.]+)$", string:banner ) ||
          egrep( pattern:"^PowerDNS Authoritative Server ([0-9.]+)$", string:banner ) ||
          egrep( pattern:"^PowerDNS Recursor ([0-9.]+)$", string:banner ) ||
          egrep( pattern:"^Knot DNS ([0-9.]+)$", string:banner ) ) {
        continue;
      }
    }
    register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"dns_banner", port:port, proto:proto );
  }
}

exit( 0 );
