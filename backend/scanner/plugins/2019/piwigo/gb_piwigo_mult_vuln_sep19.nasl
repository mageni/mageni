# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113532");
  script_version("2019-09-16T13:59:00+0000");
  script_tag(name:"last_modification", value:"2019-09-16 13:59:00 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-16 15:51:34 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-13363", "CVE-2019-13364");

  script_name("Piwigo <= 2.9.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - XSS in admin.php?page=account_billing via the vat_number, billing_name,
    company or billing_address parameter. This is exploitable via CSRF.

  - XSS in admin.php?page=notification_by_mail via the nbm_send_html_mail,
    nbm_send_mail_as, nbm_send_detailed_content, nbm_complementary_mail_content,
    nbm_send_recent_post_dates or param_submit parameter.
    This is exploitable via CSRF.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to permanently inject
  arbitrary HTML and JavaScript into the admin page.");
  script_tag(name:"affected", value:"Piwigo through version 2.9.5.");
  script_tag(name:"solution", value:"No known solution is available as of 16th September, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/154484/Piwigo-2.9.5-Cross-Site-Request-Forgery-Cross-Site-Scripting.html");

  exit(0);
}

CPE = "cpe:/a:piwigo:piwigo";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "2.9.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );