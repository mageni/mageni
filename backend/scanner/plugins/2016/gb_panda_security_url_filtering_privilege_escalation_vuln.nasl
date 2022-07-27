###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_security_url_filtering_privilege_escalation_vuln.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# Panda Security URL Filtering Privilege Escalation Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:pandasecurity:panda_security_url_filtering";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809035");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2015-7378");
  script_bugtraq_id(85887);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-14 19:02:08 +0530 (Wed, 14 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Panda Security URL Filtering Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Panda Security
  URL Filtering and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to uses of a weak ACL for
  the 'Panda Security URL Filtering' directory and installed files.");

  script_tag(name:"impact", value:"Successful exploitation will allow the
  allows local users to execute code with SYSTEM account privileges by modifying
  or substituting the main executable module.");

  script_tag(name:"affected", value:"Panda Security URL Filtering Service version
  prior to 2.0.1.46.");

  script_tag(name:"solution", value:"Upgrade to Panda Security URL Filtering Service
  version 2.0.1.46 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39670");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136607");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_panda_security_url_filtering_service_detect_win.nasl");
  script_mandatory_keys("PandaSecurity/URL/Filtering/Win/Ver");
  script_xref(name:"URL", value:"http://www.pandasecurity.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!pandaVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Panda Security URL Filtering Service version is available after installation
## The last version of URL filtering installer is 4.3.1.15 and the service version is 2.0.1.48.
## The vulnerability is solved since 2.0.1.46 version.
if(version_is_less(version:pandaVer, test_version:"2.0.1.46"))
{
  report = report_fixed_ver(installed_version:pandaVer, fixed_version:"2.0.1.46");
  security_message(data:report);
  exit(0);
}
