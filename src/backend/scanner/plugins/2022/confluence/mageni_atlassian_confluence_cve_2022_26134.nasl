###############################################################################
# Mageni Vulnerability Test
#
# Atlassian Confluence Hardcoded Password Vulnerability
#
# Authors:
# Mageni Security, LLC <mageni@mageni.net>
#
# Copyright:
# Copyright (c) 2022 Mageni Security LLC
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

CPE = "cpe:/a:atlassian:confluence";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.315158");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2022-07-27 19:33:52 +0200 (Wed, 27 Jul 2022) $");
  script_tag(name:"creation_date", value:"2022-07-27 19:33:52 +0200 (Wed, 27 Jul 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_tag(name:"cvssv2_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"cvssv2_base_score", value:"9.0");
  script_tag(name:"cvssv2_base_score_overall", value:"9.0");
  script_tag(name:"cvssv2_base_impact", value:"8.5");
  script_tag(name:"cvssv2_base_exploit", value:"10.0");
  script_tag(name:"cvssv2_em_access_vector", value:"Network");
  script_tag(name:"cvssv2_em_access_complex", value:"Low");
  script_tag(name:"cvssv2_em_authentication", value:"None");
  script_tag(name:"cvssv2_impact_ci", value:"Complete");
  script_tag(name:"cvssv2_impact_ii", value:"Partial");
  script_tag(name:"cvssv2_impact_ai", value:"Partial");

  script_tag(name:"cvssv3_base_vector", value:"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_tag(name:"cvssv3_base_score", value:"8.6");
  script_tag(name:"cvssv3_base_score_overall", value:"8.6");
  script_tag(name:"cvssv3_base_impact", value:"4.7");
  script_tag(name:"cvssv3_base_exploit", value:"3.9");
  script_tag(name:"cvssv3_em_attack_vector", value:"Network");
  script_tag(name:"cvssv3_em_attack_complex", value:"Low");
  script_tag(name:"cvssv3_em_priv_required", value:"None");
  script_tag(name:"cvssv3_em_user_interact", value:"None");
  script_tag(name:"cvssv3_scope", value:"Unchanged");
  script_tag(name:"cvssv3_impact_ci", value:"High");
  script_tag(name:"cvssv3_impact_ii", value:"Low");
  script_tag(name:"cvssv3_impact_ai", value:"Low");

  script_cve_id("CVE-2022-26138");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Confluence Hardcoded Password");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2022 Mageni Security LLC");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_confluence_detect.nasl");
  script_mandatory_keys("atlassian_confluence/installed");

  script_tag(name:"summary", value:"Atlassian Confluence is affected by a hardcoded password vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When the Questions for Confluence app is enabled on Confluence Server or Data Center, 
  it creates a Confluence user account with the username disabledsystemuser. This account is intended to aid administrators 
  that are migrating data from the app to Confluence Cloud. The disabledsystemuser account is created with a hardcoded 
  password and is added to the confluence-users group, which allows viewing and editing all non-restricted pages within 
  Confluence by default. A remote, unauthenticated attacker with knowledge of the hardcoded password could exploit this 
  to log into Confluence.");

  script_tag(name:"affected", value:"Atlassian Confluence Server and Data Center before version 7.14.3, 7.15.2, 7.13.6, 7.16.4, 7.4.17, 7.17.2");

  script_tag(name:"solution", value:"Update to 7.14.3, 7.15.2, 7.13.6, 7.16.4, 7.4.17, 7.17.2 or later versions.");

  script_xref(name:"URL", value:"https://confluence.atlassian.com/kb/faq-for-cve-2022-26138-1141988423.html");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CONFSERVER-79483");
  script_xref(name:"URL", value:"https://www.cisa.gov/uscert/ncas/current-activity/2022/07/22/atlassian-releases-security-advisory-questions-confluence-app-cve");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-26138");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "7.4.17") ||
     version_is_less(version: vers, test_version: "7.17.2") ||
     version_is_less(version: vers, test_version: "7.16.4") ||
     version_is_less(version: vers, test_version: "7.13.6") ||) {
     version_is_less(version: vers, test_version: "7.15.2") ||) {
     version_is_less(version: vers, test_version: "7.14.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.14.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
