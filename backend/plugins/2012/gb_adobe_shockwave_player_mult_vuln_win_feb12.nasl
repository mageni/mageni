###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Shockwave Player Multiple Vulnerabilities - Feb 2012 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Updated By: Rajat Mishra <rajatm@secpod.com> on 2018-02-19
# - Updated to include Installation path in the report.
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802398");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2012-0757", "CVE-2012-0759", "CVE-2012-0760", "CVE-2012-0761",
                "CVE-2012-0762", "CVE-2012-0763", "CVE-2012-0764", "CVE-2012-0766",
                "CVE-2012-0758", "CVE-2012-0771");
  script_bugtraq_id(51999, 52006, 52000, 52001, 52002, 52003, 52004, 52005, 52007);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2012-02-17 12:55:43 +0530 (Fri, 17 Feb 2012)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities - Feb 2012 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47932/");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026675");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-02.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service or
  execute arbitrary code by tricking a user into visiting a specially crafted
  web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Versions 11.6.3.633 and prior on Windows.");
  script_tag(name:"insight", value:"The flaws are due to memory corruptions errors in Shockwave 3D Asset
  component when processing malformed file.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 11.6.4.634 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://get.adobe.com/shockwave/otherversions/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];


if(version_is_less(version:vers, test_version:"11.6.4.634"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.6.4.634", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
