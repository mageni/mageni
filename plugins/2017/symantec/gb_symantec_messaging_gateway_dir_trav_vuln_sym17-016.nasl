###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_dir_trav_vuln_sym17-016.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Symantec Messaging Gateway Directory Traversal Vulnerability (SYM17-016)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812359");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-15532");
  script_bugtraq_id(102096);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-21 16:31:51 +0530 (Thu, 21 Dec 2017)");

  script_name("Symantec Messaging Gateway Directory Traversal Vulnerability (SYM17-016)");

  script_tag(name:"summary", value:"This host is installed with Symantec Messaging
  Gateway and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error which makes
  possible to access arbitrary files and directories stored on the file system
  including application source code or configuration and critical system files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a path traversal attack.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway (SMG) before 10.6.4");

  script_tag(name:"solution", value:"Upgrade to Symantec Messaging Gateway (SMG)
  10.6.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20171220_00");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
  script_mandatory_keys("symantec_smg/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version( cpe:CPE, nofork: TRUE))
  exit(0);

if(version_is_less(version:version, test_version:"10.6.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:'10.6.4');
  security_message(port: 0, data:report);
  exit(0);
}

exit(0);
