###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_crm_command_injection_vuln.nasl 12936 2019-01-04 04:46:08Z ckuersteiner $
#
# Dolibarr CRM Command Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:dolibarr:dolibarr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807851");
  script_version("$Revision: 12936 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 05:46:08 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2016-06-30 11:22:02 +0530 (Thu, 30 Jun 2016)");

  script_name("Dolibarr CRM Command Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Dolibarr CRM
  and is prone to command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due as Dolibarr is open to
  command injection via the backup tool available.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to execute arbitrary commands on the affected system.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Dolibarr CRM versions less than 3.9.1");

  script_tag(name:"solution", value:"Upgrade to Dolibarr CRM version 3.9.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137607");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_mandatory_keys("dolibarr/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.dolibarr.org");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!dolPort = get_app_port(cpe:CPE))
  exit(0);

if(!dolVer = get_app_version(cpe:CPE, port:dolPort))
  exit(0);

if(version_is_less(version:dolVer, test_version:"3.9.1")) {
  report = report_fixed_ver(installed_version:dolVer, fixed_version:"3.9.1");
  security_message(data:report, port:dolPort);
  exit(0);
}

exit(99);
