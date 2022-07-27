##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fcms_mult_rfi_vuln.nasl 11823 2018-10-10 13:57:02Z asteins $
#
# Haudenschilt Family Connections CMS (FCMS) Multiple PHP remote file inclusion vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902310");
  script_version("$Revision: 11823 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 15:57:02 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_cve_id("CVE-2010-3419");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Haudenschilt Family Connections CMS (FCMS) Multiple PHP remote file inclusion vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_dependencies("secpod_fcms_detect.nasl");
  script_mandatory_keys("fcms/detected");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied data to
'familynews.php' and 'settings.php' scripts via 'current_user_id' parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Haudenschilt Family Connections CMS (FCMS) and
is prone to multiple remote file inclusion vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to obtain
sensitive information or execute malicious PHP code in the context of the
webserver process.");
  script_tag(name:"affected", value:"Haudenschilt Family Connections CMS (FCMS) version 2.2.3");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61722");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14965/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1009-exploits/fcms-rfi.txt");
  exit(0);
}

CPE = "cpe:/a:haudenschilt:family_connections_cms";

include("host_details.inc");
include("version_func.inc");

if(!cmsPort = get_app_port(cpe:CPE)) exit(0);
if(!cmsVer = get_app_version(cpe:CPE, port:cmsPort)) exit(0);

if(version_is_equal(version:cmsVer, test_version:"2.2.3")) {
  report = report_fixed_ver(installed_version:cmsVer, fixed_version:"None");
  security_message(port:cmsPort, data:report);
  exit(0);
}

exit(99);
