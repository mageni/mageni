###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Multiple Vulnerabilities - Sep 12 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802962");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2011-3016", "CVE-2011-3021", "CVE-2011-3027", "CVE-2011-3032",
                "CVE-2011-3034", "CVE-2011-3035", "CVE-2011-3036", "CVE-2011-3037",
                "CVE-2011-3038", "CVE-2011-3039", "CVE-2011-3040", "CVE-2011-3041",
                "CVE-2011-3042", "CVE-2011-3043", "CVE-2011-3044", "CVE-2011-3050",
                "CVE-2011-3053", "CVE-2011-3059", "CVE-2011-3060", "CVE-2011-3064",
                "CVE-2011-3068", "CVE-2011-3069", "CVE-2011-3071", "CVE-2011-3073",
                "CVE-2011-3074", "CVE-2011-3075", "CVE-2011-3076", "CVE-2011-3078",
                "CVE-2011-3081", "CVE-2011-3086", "CVE-2011-3089", "CVE-2011-3090",
                "CVE-2011-3105", "CVE-2011-3913", "CVE-2011-3924", "CVE-2011-3926",
                "CVE-2011-3958", "CVE-2011-3966", "CVE-2011-3968", "CVE-2011-3969",
                "CVE-2011-3971", "CVE-2010-0682", "CVE-2012-0683", "CVE-2012-1520",
                "CVE-2012-1521", "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2829",
                "CVE-2012-2831", "CVE-2012-2842", "CVE-2012-2843", "CVE-2012-3589",
                "CVE-2012-3590", "CVE-2012-3591", "CVE-2012-3592", "CVE-2012-3593",
                "CVE-2012-3594", "CVE-2012-3595", "CVE-2012-3596", "CVE-2012-3597",
                "CVE-2012-3598", "CVE-2012-3599", "CVE-2012-3600", "CVE-2012-3601",
                "CVE-2012-3602", "CVE-2012-3603", "CVE-2012-3604", "CVE-2012-3605",
                "CVE-2012-3606", "CVE-2012-3607", "CVE-2012-3608", "CVE-2012-3609",
                "CVE-2012-3610", "CVE-2012-3611", "CVE-2012-3612", "CVE-2012-3613",
                "CVE-2012-3614", "CVE-2012-3615", "CVE-2012-3616", "CVE-2012-3617",
                "CVE-2012-3618", "CVE-2012-3620", "CVE-2012-3621", "CVE-2012-3622",
                "CVE-2012-3623", "CVE-2012-3624", "CVE-2012-3625", "CVE-2012-3626",
                "CVE-2012-3627", "CVE-2012-3628", "CVE-2012-3629", "CVE-2012-3630",
                "CVE-2012-3631", "CVE-2012-3632", "CVE-2012-3633", "CVE-2012-3634",
                "CVE-2012-3635", "CVE-2012-3636", "CVE-2012-3637", "CVE-2012-3638",
                "CVE-2012-3639", "CVE-2012-3640", "CVE-2012-3641", "CVE-2012-3642",
                "CVE-2012-3643", "CVE-2012-3644", "CVE-2012-3645", "CVE-2012-3646",
                "CVE-2012-3647", "CVE-2012-3648", "CVE-2012-3649", "CVE-2012-3651",
                "CVE-2012-3652", "CVE-2012-3653", "CVE-2012-3654", "CVE-2012-3655",
                "CVE-2012-3656", "CVE-2012-3657", "CVE-2012-3658", "CVE-2012-3659",
                "CVE-2012-3660", "CVE-2012-3661", "CVE-2012-3663", "CVE-2012-3664",
                "CVE-2012-3665", "CVE-2012-3666", "CVE-2012-3667", "CVE-2012-3668",
                "CVE-2012-3669", "CVE-2012-3670", "CVE-2012-3671", "CVE-2012-3672",
                "CVE-2012-3673", "CVE-2012-3674", "CVE-2012-3675", "CVE-2012-3676",
                "CVE-2012-3677", "CVE-2012-3678", "CVE-2012-3679", "CVE-2012-3680",
                "CVE-2012-3681", "CVE-2012-3682", "CVE-2012-3683", "CVE-2012-3684",
                "CVE-2012-3685", "CVE-2012-3686", "CVE-2012-3687", "CVE-2012-3688",
                "CVE-2012-3692", "CVE-2012-3699", "CVE-2012-3700", "CVE-2012-3701",
                "CVE-2012-3702", "CVE-2012-3703", "CVE-2012-3704", "CVE-2012-3705",
                "CVE-2012-3706", "CVE-2012-3707", "CVE-2012-3708", "CVE-2012-3709",
                "CVE-2012-3710", "CVE-2012-3711", "CVE-2012-3712");
  script_bugtraq_id(52031, 52271, 52674, 52762, 52913, 53309, 53540, 53679, 51041,
                    51641, 51911, 38368, 54680, 54203, 54386, 55534);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2012-09-17 17:25:24 +0530 (Mon, 17 Sep 2012)");
  script_name("Apple iTunes Multiple Vulnerabilities - Sep 12 (Windows)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5485");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50618/");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00001.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to conduct spoofing attacks,
  disclose potentially sensitive information, bypass certain security
  restrictions, manipulate certain data and compromise a user's system.");
  script_tag(name:"affected", value:"Apple iTunes version prior to 10.7 (10.7.0.21) on Windows");
  script_tag(name:"insight", value:"For more details about the vulnerabilities refer to the links given below.");
  script_tag(name:"solution", value:"Upgrade to Apple Apple iTunes version 10.7 or later.");
  script_tag(name:"summary", value:"This host is installed with Apple iTunes and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.apple.com/itunes/download/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

## Apple iTunes version < 10.7 (10.7.0.21)
if( version_is_less( version:vers, test_version:"10.7.0.21" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.7.0.21", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );