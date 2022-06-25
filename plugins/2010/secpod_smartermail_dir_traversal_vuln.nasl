###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartermail_dir_traversal_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# SmarterMail Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
###############################################################################

CPE = 'cpe:/a:smartertools:smartermail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902259");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");
  script_cve_id("CVE-2010-3486");
  script_bugtraq_id(43324);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SmarterMail Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61910");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15048/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1009-exploits/smartermail-traversal.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_smartermail_detect.nasl");
  script_require_ports("Services/www", 80, 9998);
  script_mandatory_keys("SmarterMail/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow remote authenticated users to
  read and write directories, files and perform malicious operations.");
  script_tag(name:"affected", value:"SmarterTools SmarterMail 7.1.3876");
  script_tag(name:"insight", value:"The flaw is due to error in the 'FileStorageUpload.ashx', which
  fails to validate the input value passed to the 'name' parameter. This allows
  remote attackers to read arbitrary files via a '../' or '%5C' or '%255c' in the
  name parameter.");
  script_tag(name:"summary", value:"This host is running SmarterMail and is prone to directory
  traversal vulnerability.");
  script_tag(name:"solution", value:"Upgrade to version 7.2.3925 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.smartertools.com/smartermail/mail-server-software.aspx");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"7.1.3876" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.2.3925" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );