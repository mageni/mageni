##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_proftpd_cmd_handling_sec_vuln_900133.nasl 13602 2019-02-12 12:47:59Z cfischer $
#
# ProFTPD Long Command Handling Security Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900133");
  script_version("$Revision: 13602 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 13:47:59 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-09-26 07:36:49 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4242");
  script_bugtraq_id(31289);
  script_copyright("Copyright (C) 2008 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_name("ProFTPD Long Command Handling Security Vulnerability");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ProFTPD/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31930/");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3115");

  script_tag(name:"summary", value:"The host is running ProFTPD Server, which is prone to cross-site
  request forgery vulnerability.");

  script_tag(name:"insight", value:"The flaw exists due to the application truncating an overly long FTP command,
  and improperly interpreting the remainder string as a new FTP command.");

  script_tag(name:"affected", value:"ProFTPD Server version prior 1.3.2rc3.");

  script_tag(name:"solution", value:"Upgrade to the latest version 1.3.2rc3.");

  script_tag(name:"impact", value:"This can be exploited to execute arbitrary FTP commands on another
  user's session privileges.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.3.2.rc3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.2rc3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );