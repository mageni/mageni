###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solarwinds_lem_cred_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# SolarWinds Log and Event Manager Hardcoded Credentials Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:solarwinds:log_and_event_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106931");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-07 11:20:51 +0700 (Fri, 07 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SolarWinds Log and Event Manager Hardcoded Credentials Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_solarwinds_log_event_manager_version.nasl");
  script_mandatory_keys("solarwinds_lem/version");

  script_tag(name:"summary", value:"SolarWinds LEM is prone to a hardcoded credentials vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Hardcoded passwords and hash digests were discovered within the LEM
appliance. These credentials were only accessible via root access.");

  script_tag(name:"affected", value:"Solarwinds LEM version 6.3.1.");

  script_tag(name:"solution", value:"Upgrade to version 6.3.1 Hotfix 5 or later.");

  script_xref(name:"URL", value:"https://www.korelogic.com/Resources/Advisories/KL-001-2017-015.txt");
  script_xref(name:"URL", value:"https://support.solarwinds.com/Success_Center/Log_Event_Manager_(LEM)/Log_and_Event_Manager_LEM_6-3-1_Hotfix_latest_ReadMe");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_equal(version: version, test_version: "6.3.1")) {
  hotfix = get_kb_item("solarwinds_lem/hotfix");
  if (!hotfix || int(hotfix) < 5) {
    report = report_fixed_ver(installed_version: version, installed_patch: hotfix, fixed_version: "6.3.1",
                              fixed_patch: "5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
