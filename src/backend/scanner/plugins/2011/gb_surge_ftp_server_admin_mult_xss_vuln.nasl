##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_surge_ftp_server_admin_mult_xss_vuln.nasl 13507 2019-02-06 15:12:15Z cfischer $
#
# SurgeFTP Admin Multiple Reflected Cross-site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801970");
  script_version("$Revision: 13507 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 16:12:15 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SurgeFTP Admin Multiple Reflected Cross-site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/surgeftp/detected");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104047/surgeftp3b6-xss.txt");
  script_xref(name:"URL", value:"http://www.securityhome.eu/os/winnt/exploit.php?eid=8349105614e4a2458040b68.10913730");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary html or scripting code in a user's browser session in the context of a vulnerable application/website.");

  script_tag(name:"affected", value:"SurgeFTP version 2.3b6.");

  script_tag(name:"insight", value:"Input passed through the POST parameters 'fname', 'last',
  'class_name', 'filter', 'domainid', and 'classid' in '/cgi/surgeftpmgr.cgi' is not sanitized properly.
  Allowing the attacker to execute HTML code into admin's browser session.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running SurgeFTP Server and is prone to multiple
  reflected cross-site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );
if( ! banner || "SurgeFTP" >!< banner )
  exit( 0 );

version = eregmatch( pattern:"SurgeFTP.*\(Version ([^)]+)\)", string:banner );

if( ! isnull( version[1] ) ) {
  if( version_is_equal( version:version[1], test_version:"2.3b6" ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );