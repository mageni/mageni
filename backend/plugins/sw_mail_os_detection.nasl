###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_mail_os_detection.nasl 13813 2019-02-21 13:07:21Z cfischer $
#
# SMTP/POP3/IMAP Server OS Identification
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111068");
  script_version("$Revision: 13813 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 14:07:21 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-12-11 14:00:00 +0100 (Fri, 11 Dec 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SMTP/POP3/IMAP OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "imap4_banner.nasl");
  script_require_ports("Services/smtp", 25, 465, 587, "Services/pop3", 110, 995, "Services/imap", 143, 993);
  script_mandatory_keys("pop3_imap_or_smtp/banner/available");

  script_tag(name:"summary", value:"This script performs SMTP/POP3/IMAP banner based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("smtp_func.inc");
include("imap_func.inc");
include("pop3_func.inc");

SCRIPT_DESC = "SMTP/POP3/IMAP Server OS Identification";

ports = smtp_get_ports();
banner_type = "SMTP banner";

foreach port( ports ) {

  banner = get_smtp_banner( port:port );
  if( ! banner )
    continue;

  if( "ESMTP" >< banner || banner =~ "^[0-9]{3}[ -].+" ) {

    if( banner == "220 ESMTP" )
      continue;

    # e.g. 220 hostname ESMTP, 220 mail.example.com ESMTP Postfix or 220 mail.example.com ESMTP ready.
    if( egrep( pattern:"^220 [^ ]+ ESMTP( Postfix| ready\.)?$", string:banner ) )
      continue;

    # e.g. 220 host ESMTP Exim 4.84_2 Tue, 01 Aug 2017 13:01:18 +0200
    if( egrep( pattern:"ESMTP Exim [0-9._]+ ", string:banner ) )
      continue;

    if( "(Gentoo Linux" >< banner || "(GENTOO/GNU)" >< banner || "(Gentoo/GNU)" >< banner ||
        "(Gentoo powered" >< banner || "(Gentoo)" >< banner || " Gentoo" >< banner || "(Gentoo/Linux" >< banner) {
      register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # e.g. 220 example.com ESMTP Xpressions Version 8.11.119 (WIN-NT) Release Build 18409 ready
    if( "Xpressions" >< banner && "(WIN-NT)" >< banner ) {
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      continue;
    }

    if( "(Ubuntu)" >< banner || "ubuntu" >< banner || " Ubuntu " >< banner ) {
      register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # 220 smtp sendmail v8.12.11 (IBM AIX 4.3)
    # 220 mail.example.com ESMTP sendmail (AIX/PPC)
    # 220-mail.example.com ESMTP AIX Sendmail 7.5.3
    # 220 mail.example.com ESMTP Sendmail AIX
    # 220 mail.example.com ESMTP Sendmail AIX4.2/UCB 8.7; Fri, 11 Jan 2019 11:50:41 +0800 (TAIST)
    # 220 mail.example.com ESMTP (AIX/IBM)
    # 220 mail.example.com IBM PROFs ESMTP gateway AIX 4.3.3 Fri, 11 Jan 2019 11:38:14 +0300
    if( "ESMTP AIX Sendmail" >< banner || "ESMTP sendmail (AIX/" >< banner || " (IBM AIX " >< banner || "ESMTP Sendmail AIX" >< banner || "ESMTP (AIX/IBM)" >< banner || "IBM PROFs ESMTP gateway AIX" >< banner ) {
      version = eregmatch( pattern:"(\(IBM AIX | AIX ?)([0-9.]+)[)/ ]", string:banner, icase:FALSE );
      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:"IBM AIX", version:version[2], cpe:"cpe:/o:ibm:aix", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"IBM AIX", cpe:"cpe:/o:ibm:aix", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "(Debian/GNU)" >< banner || "/Debian-" >< banner ) {
      if( "sarge" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "(Debian Lenny)" >< banner || "lenny" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
      } else if( "deb7" >< banner || "wheezy" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "deb8" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "/SuSE Linux" >< banner || "(Linux Suse" >< banner || "on SuSE Linux" >< banner || "(SuSE)" >< banner ) {
        register_and_report_os( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        continue;
      }

    if( "(CentOS)" >< banner || "(Centos Linux)" >< banner || "(CentOS/GNU)" >< banner ) {
      register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "on Red Hat Enterprise Linux" >< banner || "(Red Hat Enterprise Linux)" >< banner || "(RHEL" >< banner || "(RHEL/GNU)" >< banner ) {
      version = eregmatch( pattern:"\(RHEL ([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Red Hat Enterprise Linux", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "Red Hat Linux" >< banner ) {
      register_and_report_os( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "(OpenBSD" >< banner || " OpenBSD" >< banner ) {
      version = eregmatch( pattern:"\(OpenBSD ([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"OpenBSD", version:version[1], cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "(FreeBSD" >< banner || "Powered By FreeBSD" >< banner || "FreeBSD/" >< banner || " FreeBSD" >< banner || "-FreeBSD" >< banner ) {
      version = eregmatch( pattern:"\(FreeBSD( |/)([0-9.]+)", string:banner );
      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:"FreeBSD", version:version[2], cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "(NetBSD" >< banner || "/NetBSD" >< banner || "[NetBSD]" >< banner || " NetBSD " >< banner ) {
      register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "(Fedora" >< banner ) {
      if( "(Fedora Core" >< banner ) {
        version = eregmatch( pattern:"\(Fedora Core ([0-9.]+)", string:banner );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"Fedora Core", version:version[1], cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Fedora Core", cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
      } else {
        version = eregmatch( pattern:"\(Fedora ([0-9.]+)", string:banner );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"Fedora", version:version[1], cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
      }
      continue;
    }

    # ESMTP Sendmail 8.11.7p3+Sun/8.11.7; Tue, 16 Jan 2018 10:50:39 +0100 (MET)
    if( "(SunOS" >< banner || " SunOS " >< banner || "Sun/" >< banner ) {
      version = eregmatch( pattern:"\(SunOS ([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"SunOS", version:version[1], cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "(Mageia" >< banner ) {
      version = eregmatch( pattern:"\(Mageia ([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Mageia", version:version[1], cpe:"cpe:/o:mageia:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Mageia", cpe:"cpe:/o:mageia:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "(Mandriva" >< banner ) {
      version = eregmatch( pattern:"\(Mandriva MES([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Mandriva Enterprise Server", version:version[1], cpe:"cpe:/o:mandriva:enterprise_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Mandriva", cpe:"cpe:/o:mandriva:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "(Mandrake" >< banner ) {
      register_and_report_os( os:"Mandrake", cpe:"cpe:/o:mandrakesoft:mandrake_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "(Slackware" >< banner ) {
      register_and_report_os( os:"Slackware", cpe:"cpe:/o:slackware:slackware_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # Runs only on Unix-like OS variants
    if( " ESMTP Exim " >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # 220 example.com ESMTP IceWarp 11.4.6.0 x64; Tue, 22 May 2018 15:53:07 +0200
    # 220 example.com ESMTP IceWarp 11.1.2.0 RHEL6 x64; Tue, 22 May 2018 20:39:53 +0700
    # 220 example.com ESMTP IceWarp 11.1.2.0 x64; Tue, 22 May 2018 15:43:25 +0200
    # 220 example.com ESMTP IceWarp 10.0.7; Tue, 22 May 2018 20:58:03 +0700
    # 220 example.com ESMTP IceWarp 9.4.2; Tue, 22 May 2018 07:12:52 -0700
    if( " IceWarp " >< banner ) {
      # This makes sure that we're catching the RHEL6 (and similar) from above while we don't
      # report an unknown OS banner for the other variants without OS info.
      if( os_info = eregmatch( pattern:"IceWarp ([^ ;]+) ([^ ;]+) ([^ ;]+); ", string:banner, icase:FALSE ) ) {
        if( "RHEL" >< os_info[2] ) {
          version = eregmatch( pattern:"RHEL([0-9.]+)", string:os_info[2] );
          if( ! isnull( version[1] ) ) {
            register_and_report_os( os:"Red Hat Enterprise Linux", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          continue;
        } else if( "DEB" >< os_info[2] ) {
          version = eregmatch( pattern:"DEB([0-9.]+)", string:os_info[2] );
          if( ! isnull( version[1] ) ) {
            register_and_report_os( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          continue;
        } else if( "UBUNTU" >< os_info[2] ) {
          version = eregmatch( pattern:"UBUNTU([0-9.]+)", string:os_info[2] );
          if( ! isnull( version[1] ) ) {
            version = ereg_replace( pattern:"^([0-9]{1,2})(04|10)$", string:version[1], replace:"\1.\2" );
            register_and_report_os( os:"Ubuntu", version:version, cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          continue;
        }
        # nb: No continue here as we want to report an unknown OS later...
      } else {
        continue; # No OS info so just skip this IceWarp banner...
      }
    }
  }

  # Cisco Unity Connection
  if( " UnityMailer " >< banner ) {
    register_and_report_os( os:"Cisco", cpe:"cpe:/o:cisco", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    continue;
  }

  if( "for Windows ready" >< banner || "Microsoft ESMTP MAIL Service" >< banner || "ESMTP Exchange Server" >< banner ||
      "ESMTP Microsoft Exchange" >< banner || "ESMTP MS Exchange" >< banner || "on Windows" >< banner ) {
    if( "Microsoft Windows 2003" >< banner || "Windows 2003 Server" >< banner ) {
      register_and_report_os( os:'Microsoft Windows Server 2003', cpe:'cpe:/o:microsoft:windows_server_2003', banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
    } else if( "Windows 2000" >< banner ) {
      register_and_report_os( os:'Microsoft Windows 2000', cpe:'cpe:/o:microsoft:windows_2000', banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
    } else {
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
    }
    continue;
  }

  # Runs on Windows, Linux and Mac OS X
  # e.g. 220 example.com Kerio Connect 9.2.1 ESMTP ready or 220 example.com Kerio MailServer 6.5.2 ESMTP ready
  if( "Kerio Connect" >< banner || "Kerio MailServer" >< banner )
    continue;

  register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"smtp_banner", port:port );
}

ports = imap_get_ports();
banner_type = "IMAP banner";

foreach port( ports ) {

  banner = get_imap_banner( port:port );
  if( ! banner )
    continue;

  if( "IMAP4rev1" >< banner || "IMAP server" >< banner || "ImapServer" >< banner ||
      "IMAP4 Service" >< banner || " IMAP4 " >< banner ) {

    if( banner == "* OK IMAPrev1" )
      continue;

    # e.g. OK Xpressions IMAP4rev1 Version 8.11.119 (WIN-NT) Release Build 18409 ready
    if( "Xpressions" >< banner && "(WIN-NT)" >< banner ) {
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      continue;
    }

    # Cisco Unity Connection
    if( "UMSS IMAP4rev1 Server" >< banner ) {
      register_and_report_os( os:"Cisco", cpe:"cpe:/o:cisco", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "(Ubuntu)" >< banner || " ubuntu " >< banner || ( "-Debian-" >< banner && "ubuntu" >< banner ) ) {
      register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "-Debian-" >< banner || "(Debian" >< banner ) {
      if( "sarge" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "lenny" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "squeeze" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
      } else if( "deb7" >< banner || "wheezy" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "deb8" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "-Gentoo server ready" >< banner ) {
      register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "(FreeBSD" >< banner ) {
      register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "-Mageia-" >< banner ) {
      version = eregmatch( pattern:"\.mga([0-9]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Mageia", version:version[1], cpe:"cpe:/o:mageia:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Mageia", cpe:"cpe:/o:mageia:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "-Mandriva-" >< banner ) {
      version = eregmatch( pattern:"mdv([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Mandriva", version:version[1], cpe:"cpe:/o:mandriva:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Mandriva", cpe:"cpe:/o:mandriva:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "Welcome to the MANDRAKE IMAP server" >< banner || "-Mandrake-" >< banner ) {
      register_and_report_os( os:"Mandrake", cpe:"cpe:/o:mandrakesoft:mandrake_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "(Slackware" >< banner ) {
      register_and_report_os( os:"Slackware", cpe:"cpe:/o:slackware:slackware_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # Those are coming from the ID request of get_imap_banner()
    if( '"os" "Linux"' >< banner || '"os", "Linux"' >< banner ) {

      version = eregmatch( pattern:'"os-version"(, | )"([0-9.]+)', string:banner );

      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:'Linux', version:version[2], cpe:'cpe:/o:linux:kernel', banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:'Linux', cpe:'cpe:/o:linux:kernel', banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    } else if( "SUSE Linux Enterprise Server" >< banner ) {
      version = eregmatch( pattern:"SUSE Linux Enterprise Server ([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"SUSE Linux Enterprise Server", version:version[1], cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"SUSE Linux Enterprise Server", cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    } else if( '"centos"' >< banner ) {
      version = eregmatch( pattern:'"os-version"(, | )"([0-9.]+)', string:banner );
      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:"CentOS", version:version[2], cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    } else if( "CentOS release" >< banner ) {
      version = eregmatch( pattern:"CentOS release ([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"CentOS", version:version[1], cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    } else if( "Red Hat Enterprise Linux" >< banner ) {
      version = eregmatch( pattern:"Red Hat Enterprise Linux (Server|ES|AS|Client) release ([0-9.]+)", string:banner );
      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:"Red Hat Enterprise Linux " + version[1], version:version[2], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    } else if( '"OpenBSD"' >< banner ) {
      version = eregmatch( pattern:'"os-version"(, | )"([0-9.]+)', string:banner );
      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:"OpenBSD", version:version[2], cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    } else if( '"FreeBSD"' >< banner ) {
      version = eregmatch( pattern:'"os-version"(, | )"([0-9.]+)', string:banner );
      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:"FreeBSD", version:version[2], cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    } else if( '"NetBSD"' >< banner ) {
      version = eregmatch( pattern:'"os-version"(, | )"([0-9.]+)', string:banner );
      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:"NetBSD", version:version[2], cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    } else if( '"SunOS"' >< banner ) {
      version = eregmatch( pattern:'"os-version"(, | )"([0-9.]+)', string:banner );
      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:"SunOS", version:version[2], cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    # e.g. * ID ("NAME" "Zimbra" "VERSION" "8.6.0_GA_1153" "RELEASE" "20141215151116")
    } else if( '("NAME" "Zimbra"' >< banner ) {
      # Zimbra runs only on Unix-like systems
      register_and_report_os( os:'Linux', cpe:'cpe:/o:linux:kernel', banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    # Runs only on Unix-like OS variants
    } else if( " Dovecot ready." >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # * OK IceWarp 12.0.4.0 RHEL7 x64 IMAP4rev1 Tue, 22 May 2018 14:06:46 +0000
    # * OK IceWarp 11.1.2.0 RHEL6 x64 IMAP4rev1 Tue, 22 May 2018 20:46:21 +0700
    # * OK IceWarp 11.1.2.0 x64 IMAP4rev1 Tue, 22 May 2018 15:43:26 +0200
    # * OK IceWarp 9.4.0 IMAP4rev1 Tue, 22 May 2018 21:14:00 +0700
    if( " IceWarp " >< banner ) {
      # This makes sure that we're catching the RHEL6 (and similar) from above while we don't
      # report an unknown OS banner for the other variants without OS info.
      if( os_info = eregmatch( pattern:"IceWarp ([^ ]+) ([^ ]+) ([^ ]+) IMAP4rev1 ", string:banner, icase:FALSE ) ) {
        if( "RHEL" >< os_info[2] ) {
          version = eregmatch( pattern:"RHEL([0-9.]+)", string:os_info[2] );
          if( ! isnull( version[1] ) ) {
            register_and_report_os( os:"Red Hat Enterprise Linux", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          continue;
        } else if( "DEB" >< os_info[2] ) {
          version = eregmatch( pattern:"DEB([0-9.]+)", string:os_info[2] );
          if( ! isnull( version[1] ) ) {
            register_and_report_os( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          continue;
        } else if( "UBUNTU" >< os_info[2] ) {
          version = eregmatch( pattern:"UBUNTU([0-9.]+)", string:os_info[2] );
          if( ! isnull( version[1] ) ) {
            version = ereg_replace( pattern:"^([0-9]{1,2})(04|10)$", string:version[1], replace:"\1.\2" );
            register_and_report_os( os:"Ubuntu", version:version, cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
        }
        # nb: No continue here as we want to report an unknown OS later...
      } else {
        continue; # No OS info so just skip this IceWarp banner...
      }
    }
  }

  if( "The Microsoft Exchange IMAP4 service is ready" >< banner || "Microsoft Exchange Server" >< banner || "for Windows ready" >< banner ||
      ( "service is ready" >< banner && ( "(Windows/x64)" >< banner || "(Windows/x86)" >< banner ) ) || "Winmail Mail Server" >< banner ) {
    register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
    continue;
  }

  # Runs on Windows, Linux and Mac OS X
  # e.g. * OK Kerio Connect 8.0.2 IMAP4rev1 server ready or * OK Kerio MailServer 6.6.2 IMAP4rev1 server ready
  if( "Kerio Connect" >< banner || "Kerio MailServer" >< banner )
    continue;

  register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"imap_banner", port:port );
}

port = get_pop3_port( default:110 );
banner = get_pop3_banner( port:port );
if( ! banner )
  exit( 0 );

if( banner == "+OK POP3 ready" || banner == "+OK POP3" )
  exit( 0 );

banner_type = "POP3 banner";

if( "Cyrus POP3" >< banner || "Dovecot" >< banner || "POP3 Server" >< banner ||
    "Mail Server" >< banner || "POP3 server" >< banner || " POP3 " >< banner ) {

  if( "(Ubuntu)" >< banner || "ubuntu" >< banner ) {
    register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "-Debian-" >< banner || "(Debian" >< banner ) {
    if( "+sarge" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else if( "+lenny" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else if( "+squeeze" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
    } else if( "deb7" >< banner || "wheezy" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else if( "deb8" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  if( "-Gentoo server ready" >< banner ) {
    register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "-Red Hat" >< banner ) {
    register_and_report_os( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "-FreeBSD" >< banner ) {
    register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "-Fedora-" >< banner ) {
    register_and_report_os( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "-Mandriva-" >< banner ) {
    register_and_report_os( os:"Mandriva", cpe:"cpe:/o:mandriva:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Welcome to the MANDRAKE POP3 server" >< banner || "-Mandrake-" >< banner ) {
    register_and_report_os( os:"Mandrake", cpe:"cpe:/o:mandrakesoft:mandrake_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "(Slackware" >< banner ) {
    register_and_report_os( os:"Slackware", cpe:"cpe:/o:slackware:slackware_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Zimbra runs only on Unix-like systems
  if( "Zimbra POP3 server ready" >< banner ) {
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Runs only on Unix-like OS variants. Keep below the others so we're catching the distro banners first.
  if( "+OK Dovecot ready." >< banner || '* ID ("name" "Dovecot")' >< banner || "+OK Dovecot DA ready." >< banner ) {
    register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # +OK example.com IceWarp 9.2.1 POP3 Tue, 22 May 2018 17:24:54 +0300 <20180522172454@example.com>
  # +OK example.com IceWarp 11.1.2.0 RHEL6 x64 POP3 Tue, 22 May 2018 20:46:22 +0700 <20180522204622@example.com>
  # +OK example.com IceWarp 11.1.2.0 x64 POP3 Tue, 22 May 2018 15:43:26 +0200 <20180522154326@example.com>
  # +OK example.com IceWarp 12.0.4.0 RHEL7 x64 POP3 Tue, 22 May 2018 15:49:41 +0200 <20180522154941@example.com>
  if( " IceWarp " >< banner ) {
    # This makes sure that we're catching the RHEL6 (and similar) from above while we don't
    # report an unknown OS banner for the other variants without OS info.
    if( os_info = eregmatch( pattern:"IceWarp ([^ ]+) ([^ ]+) ([^ ]+) POP3 ", string:banner, icase:FALSE ) ) {
      if( "RHEL" >< os_info[2] ) {
        version = eregmatch( pattern:"RHEL([0-9.]+)", string:os_info[2] );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"Red Hat Enterprise Linux", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        exit( 0 );
      } else if( "DEB" >< os_info[2] ) {
        version = eregmatch( pattern:"DEB([0-9.]+)", string:os_info[2] );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        exit( 0 );
      } else if( "UBUNTU" >< os_info[2] ) {
        version = eregmatch( pattern:"UBUNTU([0-9.]+)", string:os_info[2] );
        if( ! isnull( version[1] ) ) {
          version = ereg_replace( pattern:"^([0-9]{1,2})(04|10)$", string:version[1], replace:"\1.\2" );
          register_and_report_os( os:"Ubuntu", version:version, cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        exit( 0 );
      }
      # nb: No exit here as we want to report an unknown OS later...
    } else {
      exit( 0 ); # No OS info so just skip this IceWarp banner...
    }
  }
}

if( "Microsoft Windows POP3 Service Version" >< banner || "for Windows" >< banner || "The Microsoft Exchange POP3 service is ready." >< banner ||
    "Microsoft Exchange Server" >< banner || "Microsoft Exchange POP3-Server" >< banner || "Winmail Mail Server" >< banner ) {
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# Runs on Windows, Linux and Mac OS X
# e.g. +OK Kerio MailServer 6.5.2 POP3 server ready <1168.1533545939@example.com>
if( "Kerio Connect" >< banner || "Kerio MailServer" >< banner )
  exit( 0 );

register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"pop3_banner", port:port );

exit( 0 );