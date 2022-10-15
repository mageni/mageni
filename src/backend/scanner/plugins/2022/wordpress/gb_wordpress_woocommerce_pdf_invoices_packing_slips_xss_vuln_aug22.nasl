# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:wpovernight:woocommerce_pdf_invoices%26_packing_slips";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170189");
  script_version("2022-10-11T10:12:36+0000");
  script_tag(name:"last_modification", value:"2022-10-11 10:12:36 +0000 (Tue, 11 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-04 14:04:48 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2022-2537");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooCommerce PDF Invoices & Packing Slips Plugin 2.14.x < 3.0.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-pdf-invoices-packing-slips/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WooCommerce PDF Invoices & Packing Slips' is
  prone to a reflected cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape some parameters before
  outputting them back in an attributes of an admin page, leading to reflected cross-site scripting.
  This is a re-introduction of CVE-2021-24991 in 2.14.0.");

  script_tag(name:"affected", value:"WordPress WooCommerce PDF Invoices & Packing Slips plugin
  version 2.14.0 through 3.0.0.");

  script_tag(name:"solution", value:"Update to version 3.0.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ae613148-85d8-47a0-952d-49c29584676f");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"2.14.0", test_version_up:"3.0.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.0.1", install_path:location );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
