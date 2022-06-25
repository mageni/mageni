##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_softalk_mail_serv_imap_dos_vuln_900119.nasl 13409 2019-02-01 13:13:33Z cfischer $
#
# Softalk Mail Server IMAP Denial of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900119");
  script_version("$Revision: 13409 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 14:13:33 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_cve_id("CVE-2008-4041");
  script_bugtraq_id(30970);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Softalk Mail Server IMAP Denial of Service Vulnerability");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/softalk/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31715/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/495896");
  script_xref(name:"URL", value:"http://www.softalkltd.com/products/download_wm.asp");

  script_tag(name:"summary", value:"The host is running Softalk Mail Server, which is prone to denial
  of service vulnerability.");

  script_tag(name:"insight", value:"The issue is due to inadequate boundary checks on specially
  crafted IMAP commands. The service can by crashed sending malicious IMAP command sequences.");

  script_tag(name:"affected", value:"Softalk Mail Server versions 8.5.1 and prior on Windows (all).");

  script_tag(name:"solution", value:"Upgrade to Softalk Mail Server version 8.6.0 or later.");

  script_tag(name:"impact", value:"Successful exploitation crashes the affected server denying the
  service to legitimate users.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("imap_func.inc");

port = get_imap_port( default:143 );
banner = get_imap_banner( port:port );
if( ! banner ) exit( 0 );

if( egrep( pattern:"Softalk Mail Server ([0-7]\..*|8\.([0-4](\..*)?|5(\.0" +
                   "(\..*)?)?|5\.1))[^.0-9]", string:banner ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );