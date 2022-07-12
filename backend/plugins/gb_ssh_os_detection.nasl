###############################################################################
# OpenVAS Vulnerability Test
#
# SSH OS Identification
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.105586");
  script_version("2019-05-07T06:30:33+0000");
  script_tag(name:"last_modification", value:"2019-05-07 06:30:33 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2016-03-23 14:28:40 +0100 (Wed, 23 Mar 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSH OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"summary", value:"This script performs SSH banner based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

SCRIPT_DESC = "SSH OS Identification";
BANNER_TYPE = "SSH banner";

port = get_ssh_port( default:22 );
banner = get_ssh_server_banner( port:port );
if( ! banner  || banner == "" || isnull( banner ) )
  exit( 0 );

textbanner = get_kb_item( "SSH/textbanner/" + port );

# nb: Generic banner without OS info covered by gb_dropbear_ssh_detect.nasl
if( egrep( pattern:"^SSH-([0-9.]+)-dropbear[_-]([0-9.]+)$", string:banner ) ||
    banner == "SSH-2.0-dropbear" ) {
  exit( 0 );
}

# nb: Supports Linux, UNIX, BSD, Solaris, OS/2 and Windows so exit for a generic banner without OS info...
if( banner =~ "^SSH-2.0-libssh[_-][0-9.]+$" ||
    banner == "SSH-2.0-libssh" ) {
  exit( 0 );
}

# No OS info...
if( banner == "SSH-2.0-SSH_2.0" )
  exit( 0 );

# Vendor: "Works with any OS vendor and will function without an OS if needed"
if( egrep( pattern:"^SSH-2\.0-RomSShell_[0-9.]+$", string:banner ) ||
    banner == "SSH-2.0-RomSShell" )
  exit( 0 );

# Cross-platform / platform independent
if( banner == "SSH-2.0-Mocana SSH" ||
    egrep( pattern:"^SSH-2\.0-Mocana SSH [0-9.]+$", string:banner ) )
  exit( 0 );

if( egrep( pattern:"^SSH-1\.99-OpenSSH_[0-9.p]+$", string:banner ) ||
    egrep( pattern:"^SSH-2\.0-OpenSSH_[0-9.p]+-FIPS_hpn[0-9v]+$", string:banner ) || # SSH-2.0-OpenSSH_6.1-FIPS_hpn13v11
    egrep( pattern:"^SSH-2\.0-OpenSSH_[0-9.p]+(\-FIPS\(capable\))?$", string:banner ) ||
    banner == "SSH-2.0-OpenSSH" ||
    banner == "SSH-2.0-OpenSSH_" )
  exit( 0 );

# Covered in gb_mikrotik_router_routeros_ssh_detect.nasl
if( banner == "SSH-2.0-ROSSSH" )
  exit( 0 );

#For banners see e.g. https://github.com/BetterCrypto/Applied-Crypto-Hardening/blob/master/unsorted/ssh/ssh_version_strings.txt

# Order matters, as some banners can include several keywords.
# Ubuntu pattern for new releases last checked on 11/2017 (up to 17.10, LTS releases: 12.04 up to 12.04.5, 14.04 up to 14.04.5, 16.04 up to 16.04.3)
if( "ubuntu" >< tolower( banner ) )
{
  if( "SSH-2.0-OpenSSH_3.8.1p1 Debian 1:3.8.1p1-11ubuntu3" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"4.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_3.9p1 Debian-1ubuntu2" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"5.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.1p1 Debian-7ubuntu4" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"5.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.2p1 Debian-7ubuntu3" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"6.06", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.3p2 Debian-5ubuntu1" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"6.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.3p2 Debian-8ubuntu1" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"7.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.6p1 Debian-5ubuntu0" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.1p1 Debian-3ubuntu1" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"8.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.1p1 Debian-5ubuntu1" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"9.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.1p1 Debian-6ubuntu2" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"9.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu3" >< banner || "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu4" >< banner ||
      "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu5" >< banner || "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu6" >< banner ||
      "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"10.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.5p1 Debian-4ubuntu3" >< banner || "SSH-2.0-OpenSSH_5.5p1 Debian-4ubuntu4" >< banner || "SSH-2.0-OpenSSH_5.5p1 Debian-4ubuntu5" >< banner)
  {
    register_and_report_os( os:"Ubuntu", version:"10.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.8p1 Debian-1ubuntu3" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"11.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.8p1 Debian-7ubuntu1" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"11.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"12.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.0p1 Debian-3ubuntu" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"12.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.1p1 Debian-3ubuntu" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.2p2 Ubuntu-6" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"13.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.6p1 Ubuntu-2" >< banner || "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-8" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.9p1 Ubuntu-2" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.3p1 Ubuntu-1" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.5p1 Ubuntu-10" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.7p1 Ubuntu-4" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.9p1 Ubuntu-10" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # We don't know the OS version
  register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "Debian" >< banner || "Raspbian" >< banner )
{
  # Special case on Ubuntu 7.10
  if( "SSH-2.0-OpenSSH_4.6p1 Debian-5build1" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Another special case on Ubuntu 13.04
  if( "SSH-2.0-OpenSSH_6.1p1 Debian-4" >< banner )
  {
    register_and_report_os( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.1p1 Debian" >< banner )
  {
    register_and_report_os( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.5p1 Debian-6" >< banner )
  {
    register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
  if( "SSH-2.0-OpenSSH_6.0p1 Debian-4" >< banner || ( "~bpo7" >< banner && "SSH-2.0-OpenSSH_" >< banner ) )
  {
    register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.7p1 Debian-5" >< banner || "SSH-2.0-OpenSSH_6.7p1 Raspbian-5" >< banner || ( "~bpo8" >< banner && "SSH-2.0-OpenSSH_" >< banner )  )
  {
    register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.4p1 Debian-10" >< banner || "SSH-2.0-OpenSSH_7.4p1 Raspbian-10" >< banner || ( "~bpo9" >< banner && "SSH-2.0-OpenSSH_" >< banner ) )
  {
    register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # We don't know the OS version
  register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: "VersionAddendum" in https://www.freebsd.org/cgi/man.cgi?query=sshd_config
else if( "FreeBSD" >< banner )
{
  if( "SSH-2.0-OpenSSH_4.5p1 FreeBSD-20061110" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"7.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.1p1 FreeBSD-20080901" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"7.2", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.2p1 FreeBSD-20090522" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"8.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.4p1 FreeBSD-20100308" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"8.1", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.8p2_hpn13v11 FreeBSD-20110503" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"9.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.4_hpn13v11 FreeBSD-20131111" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"10.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.2 FreeBSD-20160310" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"11.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.2 FreeBSD-20161230" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"11.1", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.5 FreeBSD-20170903" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"11.2", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.8 FreeBSD-20180909" >< banner )
  {
    register_and_report_os( os:"FreeBSD", version:"12.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # We don't know the OS version
  register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "OpenBSD" >< banner )
{
  # We don't know the OS version
  register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "NetBSD" >< banner )
{
  # We don't know the OS version
  register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "CISCO_WLC" >< banner )
{
  register_and_report_os( os:"Cisco Wireless Lan Controller", cpe:"cpe:/o:cisco:wireless_lan_controller", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# SSH-1.99-Cisco-1.25
# SSH-2.0-Cisco-1.25
# SSH-1.99-Cisco-2.0
# SSH-2.0-Cisco-2.0
else if( banner =~ "^SSH-[0-9.]+-Cisco-[0-9.]+" )
{
  register_and_report_os( os:"Cisco IOS", cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( eregmatch( string:banner, pattern:"(cisco|FIPS User Access Verification)", icase:TRUE ) || "Cisco Systems, Inc. All rights Reserved" >< textbanner )
{
  register_and_report_os( os:"Cisco", cpe:"cpe:/o:cisco", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( banner =~ "SSH-[0-9.]+-Sun_SSH" )
{
  register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "SSH-2.0-NetScreen" >< banner )
{
  register_and_report_os( os:"NetScreen ScreenOS", cpe:"cpe:/o:juniper:netscreen_screenos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( eregmatch( string:banner, pattern:"SSH-2.0-xxxxxxx|FortiSSH" ) )
{
  register_and_report_os( os:"FortiOS", cpe:"cpe:/o:fortinet:fortios", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "OpenVMS" >< banner )
{
  register_and_report_os( os:"OpenVMS", cpe:"cpe:/o:hp:openvms", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "SSH-2.0-MS_" >< banner )
{
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows_10:-:-:iot", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# SSH-2.0-WeOnlyDo 2.4.3
# SSH-2.0-WeOnlyDo-wodFTPD 3.3.0.424
# Both from http://www.freesshd.com running on Windows only
else if( "SSH-2.0-WeOnlyDo" >< banner )
{
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

else if( "SSH-2.0-mpSSH_" >< banner )
{
  register_and_report_os( os:"HP iLO", cpe:"cpe:/o:hp:integrated_lights-out", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "SSH-2.0-Data ONTAP SSH" >< banner )
{
  register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Embedded Linux
else if( "SSH-2.0-moxa_" >< banner )
{
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SolarWinds Network Configuration Manager (NCM) running on Windows only.
else if( "Network ConfigManager SCP Server" >< banner )
{
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# SSH-2.0-OpenSSH_for_Windows_7.9
else if( "OpenSSH_for_Windows" >< banner )
{
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_netapp_data_ontap_consolidation.nasl
else if( egrep( pattern:"SSH.+Data ONTAP SSH", string:banner ) )
{
  register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"ssh_banner", port:port );

exit( 0 );
