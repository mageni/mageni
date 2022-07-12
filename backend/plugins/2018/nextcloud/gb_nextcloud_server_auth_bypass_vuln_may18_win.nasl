###############################################################################
# OpenVAS Vulnerability Test
#
# Nextcloud Server Authorization Bypass Vulnerability May18 (Windows)
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813324");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-0936");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-02 18:06:32 +0530 (Wed, 02 May 2018)");
  script_name("Nextcloud Server Authorization Bypass Vulnerability May18 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Nextcloud Server
  and is prone to authorization bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a missing ownership
  check while changing the scope of app passwords of other users.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to change the scope of app passwords of other users. Note that the app passwords
  themselves where neither disclosed nor could the error be misused to identify as
  another user.");

  script_tag(name:"affected", value:"Nextcloud Server before 11.0.7 and 12.0.5");

  script_tag(name:"solution", value:"Upgrade to version 11.0.7 or 12.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=nc-sa-2018-001");
  script_xref(name:"URL", value:"https://nextcloud.com");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!nxport = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:nxport, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"11.0.7")){
  fix = "11.0.7";
}

else if(version_in_range(version:vers, test_version:"12.0", test_version2:"12.0.4")){
  fix = "12.0.5";
}

if(fix)
{
 report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
 security_message(port:nxport, data:report);
 exit(0);
}

exit(0);
