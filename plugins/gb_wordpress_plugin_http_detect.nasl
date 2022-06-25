# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later # See https://spdx.org/licenses/
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
  script_oid("1.3.6.1.4.1.25623.1.0.113634");
  script_version("2020-01-28T16:48:26+0000");
  script_tag(name:"last_modification", value:"2020-01-28 16:48:26 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 10:34:33 +0100 (Mon, 27 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WordPress Plugin Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks which WordPress plugins are installed on the target system.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );


if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( dir == "/" ) dir = "";


#nb: The format is: "[README_URL]", "[NAME]#---#[DETECTION PATTERN]#---#[VERSION REGEX]#---#[CPE]"
plugins = make_array(
"accelerated-mobile-pages/readme.txt", "AMP for WP#---#Accelerated Mobile Pages ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:ahmed_kaludi:accelerated-mobile-pages",
"ad-inserter/readme.txt", "Ad Inserter#---#=== Ad Inserter#---#Stable tag: ([0-9.]+)#---#cpe:/a:igor_funa:ad-inserter",
"adamrob-parallax-scroll/readme.txt", "Parallax Scroll#---#Parallax Scroll#---#Stable tag: ([0-9.]+)#---#cpe:/a:adamrob:adamrob-parallax-scroll",
"adaptive-images/readme.txt", "Adaptive Images#---#=== Adaptive Images for WordPress ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:nevma:adaptive-images",
"add-link-to-facebook/readme.txt", "add-link-to-facebook#---#Add Link to Facebook#---#Stable tag: ([0-9.]+)#---#cpe:/a:readygraph:add-link-to-facebook",
"advanced-cf7-db/README.txt", "Advanced Contact form 7 DB#---#=== Advanced Contact form 7 DB ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:vsourz:advanced-cf7-db",
"advanced-custom-fields/readme.txt", "Advanced Custom Fields#---#=== Advanced Custom Fields#---#= ([0-9.]+) =#---#cpe:/a:elliot_condon:advanced-custom-fields",
"affiliates-manager/readme.txt", "Affiliates Manager#---#=== Affiliates Manager#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp_insider:affiliates-manager",
"ag-custom-admin/readme.txt", "Absolutely Glamorous Custom Admin#---#=== (Absolutely Glamorous|AG) Custom Admin#---#Stable tag: ([0-9.]+)#---#cpe:/a:cusmin:ag-custom-admin",
"all-in-one-wp-security-and-firewall/readme.txt", "All In One WP Security & Firewall#---#=== All In One WP Security & Firewall#---#= ([0-9.]+) =#---#cpe:/a:tipsandtricks-hq:all-in-one-wp-security-and-firewall",
"backwpup/readme.txt", "BackWPup#---#(BackWPup|WordPress Backup Plugin)#---#Stable tag: ([0-9.]+)#---#cpe:/a:inpsyde:backwpup",
"banner-management-for-woocommerce/readme.txt", "Category Banner Management for Woocommerce#---#=== Woocommerce Category Banner Management ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:multidots:banner-management-for-woocommerce",
"bft-autoresponder/readme.txt", "Arigato Autoresponder and Newsletter#---#(=== Arigato Autoresponder and Newsletter ===|Plugin Name: Arigato Autoresponder and Newsletter)#---#Stable tag: ([0-9.]+)#---#cpe:/a:kiboko_labs:bft-autoresponder",
"blog2social/readme.txt", "Blog2Social#---#Blog2Social#---#Stable tag: ([0-9.]+)#---#cpe:/a:blog2social:blog2social",
"bold-page-builder/readme.txt", "Bold Page Builder#---#=== Bold Page Builder#---#= ([0-9.]+) =#---#cpe:/a:bold-themes:bold-page-builder",
"booking/readme.txt", "Booking Calendar#---#=== Booking Calendar ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpdevelop:booking",
"bookly-responsive-appointment-booking-tool/readme.txt", "Bookly#---#=== Bookly #1 WordPress Booking Plugin#---#Stable tag: ([0-9.]+)#---#cpe:/a:bookly:bookly-responsive-appointment-booking-tool",
"broken-link-checker/readme.txt", "Broken Link Checker#---#=== Broken Link Checker#---#Stable tag: ([0-9.]+)#---#cpe:/a:managewp:broken-link-checker",
"calculated-fields-form/README.txt", "Calculated Fields Form#---#=== Calculated Fields Form#---#= ([0-9.]+) =#---#cpe:/a:codepeople:calculated-fields-form",
"calendar/readme.txt", "Calendar#---#=== Calendar ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:kieranoshea:calendar",
"captcha/readme.txt", "captcha#---#Captcha by BestWebSoft#---#Stable tag: ([0-9.]+)#---#cpe:/a:simplywordpress:captcha",
"cleantalk-spam-protect/readme.txt", "Spam protection, AntiSpam, FireWall by CleanTalk#---#CleanTalk#---#= ([0-9.]+) [^=]*=#---#cpe:/a:cleantalk:cleantalk-spam-protect",
"codepress-admin-columns/readme.txt", "Admin Columns#---#Admin Columns ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:admincolumns:codepress-admin-columns",
"community-events/readme.txt", "Community Events#---#Community Events#---#Stable tag: ([0-9.]+)#---#cpe:/a:ylefebvre:community-events",
"companion-auto-update/readme.txt", "Companion Auto Update#---#=== (Companion Auto Update|Companion Revision Manager)#---#Stable tag: ([0-9.]+)#---#cpe:/a:papin_schipper:companion-auto-update",
"contact-form-builder/readme.txt", "WDContactFormBuilder#---#=== Contact Form Builder#---#Stable tag: ([0-9.]+)#---#cpe:/a:web-dorado:contact-form-builder",
"contact-form-maker/readme.txt", "Contact Form by WD#---#=== Contact Form#---#Stable tag: ([0-9.]+)#---#cpe:/a:web-dorado:contact-form-maker",
"contact-form-to-email/readme.txt", "Contact Form Email#---#=== Contact Form Email ===#---#= ([0-9.]+) =#---#cpe:/a:codepeople:contact-form-to-email",
"count-per-day/readme.txt", "count-per-day#---#=== Count per Day ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:easyplugin:count-per-day",
"crelly-slider/readme.txt", "Crelly Slider#---#=== Crelly Slider#---#Stable tag: ([0-9.]+)#---#cpe:/a:fabio_rinaldi:crelly-slider",
"cta/readme.txt", "WordPress Calls to Action#---#WordPress Calls to Action#---#Stable tag: ([0-9.]+)#---#cpe:/a:inboundnow:cta",
"custom-field-suite/readme.txt", "Custom Field Suite#---#=== Custom Field Suite ===#---#= ([0-9.]+)#---#cpe:/a:matt_gibbs:custom-field-suite",
"custom-sidebars/readme.txt", "Custom Sidebars#---#=== Custom Sidebars#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpmudev:custom-sidebars",
"disable-comments/readme.txt", "Disable Comments#---#Disable Comments#---#= ([0-9.]+) =#---#cpe:/a:rayofsolaris:disable-comments",
"download-manager/readme.txt", "Download Manager#---#Download Manager ===#---#= ([0-9.]+) =#---#cpe:/a:w3_eden:download-manager",
"duplicator/readme.txt", "Duplicator#---#Duplicator - WordPress Migration Plugin#---#Stable tag: ([0-9.]+)#---#cpe:/a:snapcreek:duplicator",
"easy-custom-auto-excerpt/readme.txt", "Easy Custom Auto Excerpt#---#=== Easy Custom Auto Excerpt ===#---#= ([0-9.]+) =#---#cpe:/a:tonjoo:easy-custom-auto-excerpt",
"easy-digital-downloads/readme.txt", "Easy Digital Downloads#---#=== Easy Digital Downloads#---#Stable tag: ([0-9.]+)#---#cpe:/a:easydigitaldownloads:easy-digital-downloads",
"easy-fancybox/readme.txt", "Easy FancyBox#---#=== Easy FancyBox#---#Stable tag: ([0-9.]+)#---#cpe:/a:ravanh:easy-fancybox",
"easy-testimonials/readme.txt", "Easy Testimonials#---#Easy Testimonials#---#Stable tag: ([0-9.]+)#---#cpe:/a:goldplugins:easy-testimonials",
"easy-wp-smtp/readme.txt", "Easy WP SMTP#---#Easy WP SMTP#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp-ecommerce:easy-wp-smtp",
"elementor/readme.txt", "Elementor Page Builder#---#=== Elementor#---#Stable tag: ([0-9.]+)#---#cpe:/a:elementor:elementor",
"email-subscribers/readme.txt", "Email Subscribers & Newsletters#---#=== Email Subscribers#---#Stable tag: ([0-9.]+)#---#cpe:/a:icegram:email-subscribers",
"events-manager/readme.txt", "Events Manager#---#=== Events Manager ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:marcus_sykes:events-manager",
"everest-forms/readme.txt", "Everest Forms#---#Everest Forms#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpeverest:everest-forms",
"export-users-to-csv/readme.txt", "export-users-to-csv#---#(Export users data and metadata to a csv file.|A WordPress plugin that exports user data and meta data.)#---#Stable tag: ([0-9.]+)#---#cpe:/a:mattcromwell:export-users-to-csv",
"facebook-by-weblizar/readme.txt", "Social LikeBox & Feed#---#=== (Facebook|Social LikeBox)#---#Stable tag: ([0-9.]+)#---#cpe:/a:weblizar:facebook-by-weblizar",
"facebook-for-woocommerce/readme.txt", "Facebook for WooCommerce#---#=== Facebook for WooCommerce#---#= ([0-9.]+) (- [0-9-]+ )?=#---#cpe:/a:facebook:facebook-for-woocommerce",
"font-organizer/readme.txt", "font-organizer#---#=== Font Organizer ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:hive:font-organizer",
"foogallery/README.txt", "FooGallery#---#=== FooGallery#---#== Changelog.*#---#cpe:/a:fooplugins:foogallery",
"form-maker/readme.txt", "FormMaker by 10Web#---#= Form Maker#---#Stable tag: ([0-9.]+)#---#cpe:/a:10web:form-maker",
"formidable/readme.txt", "Formidable Form Builder#---#(=== Formidable|Formidable Forms Builder for WordPress ===)#---#= ([0-9.]+) =#---#cpe:/a:strategy11:formidable",
"forminator/readme.txt", "Forminator#---#=== Forminator#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpmudev:forminator",
"fv-wordpress-flowplayer/readme.txt", "FV Flowplayer Video Player#---#=== (Flowplayer|FV) (Wordpress|Flowplayer)#---#== Changelog.*#---#cpe:/a:foliovision:fv-wordpress-flowplayer",
"gallery-bank/readme.txt", "Gallery Bank#---#Gallery Bank#---#Stable tag: ([0-9.]+)#---#cpe:/a:tech-banker:gallery-bank",
"gd-rating-system/readme.txt", "GD Rating System#---#GD Rating System#---#Version: ([0-9.]+)#---#cpe:/a:dev4press:gd-rating-system",
"give/readme.txt", "GiveWP#---#=== Give#---#Stable tag: ([0-9.]+)#---#cpe:/a:givewp:give",
"google-analyticator/readme.txt", "Google Analyticator#---#Google Analyticator#---#Stable tag: ([0-9.]+)#---#cpe:/a:sumome:google-analyticator",
"google-document-embedder/readme.txt", "Google Doc Embedder#---#=== Google Doc Embedder#---#= ([0-9.]+) =#---#cpe:/a:kevin_davis:google-document-embedder",
"gwolle-gb/readme.txt", "Gwolle Guestbook#---#Gwolle Guestbook#---#Stable tag: ([0-9.]+)#---#cpe:/a:zenoweb:gwolle-gb",
"hrm/readme.txt", "WP Human Resource Management#---#=== WP Human Resource Management ===#---#= ([0-9.]+) -#---#cpe:/a:asaquzzaman:hrm",
"icegram/readme.txt", "Icegram#---#(=== Icegram|Icegram ===)#---#Stable tag: ([0-9.]+)#---#cpe:/a:icegram:icegram",
"igniteup/readme.txt", "IgniteUp#---#=== IgniteUp#---#Stable tag: ([0-9.]+)#---#cpe:/a:ceylon_systems:igniteup",
"import-users-from-csv-with-meta/readme.txt", "Import users from CSV with meta#---#=== Import users from CSV with meta#---#Stable tag: ([0-9.]+)#---#cpe:/a:codection:import-users-from-csv-with-meta",
"insert-php/readme.txt", "Woody ad snippets#---#=== (Insert PHP|PHP code snippets|Woody ad snippets)#---#= ([0-9.]+) =#---#cpe:/a:webcraftic:insert-php",
"insta-gallery/readme.txt", "Social Feed Gallery#---#(Instagram Gallery|=== WP Social Feed Gallery)#---#Stable tag: ([0-9.]+)#---#cpe:/a:quadlayers:insta-gallery",
"kingcomposer/readme.txt", "KingComposer#---#KingComposer#---#= ([0-9.]+) \(#---#cpe:/a:king-theme:kingcomposer",
"launcher/readme.txt", "Launcher#---#=== Launcher#---#Stable tag: ([0-9.]+)#---#cpe:/a:mythemeshop:launcher",
"login-or-logout-menu-item/readme.txt", "Login or Logout Menu Item#---#=== Login or Logout Menu Item#---#Stable tag: ([0-9.]+)#---#cpe:/a:cartpauj:login-or-logout-menu-item",
"loginizer/readme.txt", "Loginizer#---#Loginizer#---#Stable tag: ([0-9.]+)#---#cpe:/a:raj_kothari:loginizer",
"loginpress/readme.txt", "LoginPress#---#(=== LoginPress|LoginPress ===)#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpbrigade:loginpress",
"master-slider/README.txt", "Master Slider#---#=== Master Slider#---#Stable tag: ([0-9.]+)#---#cpe:/a:averta:master-slider",
"media-file-manager/readme.txt", "media-file-manager#---#Media File Manager#---#Stable tag: ([0-9.]+)#---#cpe:/a:tempspace:media-file-manager",
"media-from-ftp/readme.txt", "Media from FTP#---#=== Media From FTP ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:riverforest-wp:media-from-ftp",
"meta-box/readme.txt", "Meta Box#---#=== Meta Box#---#Stable tag: ([0-9.]+)#---#cpe:/a:metabox:meta-box",
"miniorange-saml-20-single-sign-on/readme.txt", "SAML SP Single Sign On - SSO login#---#(miniOrange|Single Sign On)#---#Stable tag: ([0-9.]+)#---#cpe:/a:miniorange:miniorange-saml-20-single-sign-on",
"my-calendar/readme.txt", "My Calendar#---#=== My Calendar#---#= ([0-9.]+) =#---#cpe:/a:joedolson:my-calendar",
"newstatpress/readme.txt", "NewStatPress#---#(NewStatPress|StatPress)#---#Stable tag: ([0-9.]+)#---#cpe:/a:stefano_tognon:newstatpress",
"nextgen-gallery/readme.txt", "NextGEN Gallery#---#NextGEN Gallery#---#Stable tag: ([0-9.]+)#---#cpe:/a:imagely:nextgen-gallery",
"ninja-forms/readme.txt", "Ninja Forms#---#=== Ninja Forms#---#Stable tag: ([0-9.]+)#---#cpe:/a:thewpninjas:ninja-forms",
"one-click-ssl/readme.txt", "One Click SSL#---#=== One Click SSL#---#Stable tag: ([0-9.]+)#---#cpe:/a:tribulant:one-click-ssl",
"onesignal-free-web-push-notifications/readme.txt", "OneSignal - Web Push Notifications#---#=== OneSignal#---#Stable tag: ([0-9.]+)#---#cpe:/a:onesignal:onesignal-free-web-push-notifications",
"online-lesson-booking-system/readme.txt", "Online Lesson Booking#---#=== Online Lesson Booking ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:sukimalab:online-lesson-booking-system",
"option-tree/readme.txt", "OptionTree#---#=== OptionTree#---#Stable tag: ([0-9.]+)#---#cpe:/a:valendesigns:option-tree",
"paid-memberships-pro/readme.txt", "Paid Memberships Pro#---#Paid Memberships Pro#---#Stable tag: ([0-9.]+)#---#cpe:/a:strangerstudios:paid-memberships-pro",
"peters-login-redirect/readme.txt", "Peter's Login Redirect#---#(Peter's Login|Defining redirect rules per role)#---#= ([0-9.]+) =#---#cpe:/a:peter_keung:peters-login-redirect",
"photo-gallery/readme.txt", "Photo Gallery by 10Web#---#(=== Gallery ===|Photo Gallery by 10Web|Photo Gallery by WD)#---#Stable tag: ([0-9.]+)#---#cpe:/a:10web:photo-gallery",
"pixelyoursite/readme.txt", "PixelYourSite#---#===PixelYourSite#---#Stable tag: ([0-9.]+)#---#cpe:/a:pixelyoursite:pixelyoursite",
"pods/readme.txt", "Pods#---#=== Pods#---#Stable tag: ([0-9.]+)#---#cpe:/a:pods:pods",
"popup-builder/readme.txt", "Popup Builder#---#Popup Builder#---#== Changelog ==.*#---#cpe:/a:sygnoos:popup-builder",
"print-my-blog/readme.txt", "Print My Blog#---#=== Print My Blog ===#---#= ([0-9.]+)#---#cpe:/a:cmljnelson:print-my-blog",
"profile-builder/readme.txt", "Profile Builder#---#Profile Builder#---#Stable tag: ([0-9.]+)#---#cpe:/a:cozmoslabs:profile-builder",
"ps-phpcaptcha/readme.txt", "PS PHPCaptcha WP#---#=== PS PHPCaptcha WP ===#---#= ([0-9.]+) =#---#cpe:/a:peter_stimpel:ps-phpcaptcha",
"relevanssi/readme.txt", "Relevanssi#---#Relevanssi - A Better Search#---#Stable tag: ([0-9.]+)#---#cpe:/a:mikkosaari:relevanssi",
"responsive-menu/readme.txt", "Responsive Menu#---#=== Responsive Menu#---#Stable tag: ([0-9.]+)#---#cpe:/a:expresstech:responsive-menu",
"role-scoper/readme.txt", "Role Scoper#---#Role Scoper#---#Stable tag: ([0-9.]+)#---#cpe:/a:agapetry:role-scoper",
"safe-svg/readme.txt", "Safe SVG#---#=== Safe SVG ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:enshrined:safe-svg",
"sagepay-server-gateway-for-woocommerce/readme.txt", "SagePay Server Gateway for WooCommerce#---#=== SagePay Server Gateway for WooCommerce ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:patsatech:sagepay-server-gateway-for-woocommerce",
"seo-by-rank-math/readme.txt", "WordPress SEO Plugin - Rank Math#---#=== WordPress SEO Plugin - Rank Math#---#Stable tag: ([0-9.]+)#---#cpe:/a:rankmath:seo-by-rank-math",
"shapepress-dsgvo/README.txt", "WP DSGVO Tools#---#=== WP DSGVO Tools#---#Stable tag: ([0-9.]+)#---#cpe:/a:legalweb:shapepress-dsgvo",
"simple-301-redirects-addon-bulk-uploader/readme.txt", "Simple 301 Redirects - Addon - Bulk Uploader#---#=== Simple 301 Redirects#---#= ([0-9.]+) =#---#cpe:/a:webcraftic:simple-301-redirects-addon-bulk-uploader",
"simple-download-monitor/readme.txt", "Simple Download Monitor#---#Simple Download Monitor#---#Stable tag: ([0-9.]+)#---#cpe:/a:tipsandtricks-hq:simple-download-monitor",
"simple-fields/readme.txt", "simple-fields#---#=== Simple Fields#---#Stable tag: ([0-9.]+)#---#cpe:/a:eskapism:simple-fields",
"simple-membership/readme.txt", "Simple Memvership#---#=== Simple Membership#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp_insider:simple-membership",
"simple-social-buttons/readme.txt", "Simple Social Media Share Buttons#---#=== Simple Social Media Share Buttons#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpbrigade:simple-social-buttons",
"slideshow-gallery/readme.txt", "Slideshow Gallery#---#=== Slideshow Gallery ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:tribulant:slideshow-gallery",
"smart-google-code-inserter/readme.txt", "Smart Google Code Inserter#---#Stable tag: ([0-9.]+)#---#cpe:/a:oturia:smart-google-code-inserter",
"social-networks-auto-poster-facebook-twitter-g/readme.txt", "NextScripts: Social Networks Auto-Poster#---#=== NextScripts: Social Networks Auto-Poster ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:nextscripts:social-networks-auto-poster-facebook-twitter-g",
"social-pug/readme.txt", "Social Sharing Buttons - Grow#---#(Social Sharing Buttongs|Grow|Social Pug)#---#Stable tag: ([0-9.]+)#---#cpe:/a:mediavine:social-pug",
"social-warfare/readme.txt", "Social Warfare#---#Social Warfare ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:warfareplugins:social-warfare",
"spam-byebye/readme.txt", "spam-byebye#---#SPAM-BYEBYE#---#Stable tag: ([0-9.]+)#---#cpe:/a:ohtan:spam-byebye",
"stops-core-theme-and-plugin-updates/readme.txt", "Easy Updates Manager#---#=== (Easy Updates Manager|Disable Updates Manager|Disable All Updates)#---#= ([0-9.]+) (- [0-9-]+ )?=#---#cpe:/a:easyupdatesmanager:stops-core-theme-and-plugin-updates",
"supportcandy/readme.txt", "SupportCandy#---#=== SupportCandy ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:supportcandy:supportcandy",
"svg-vector-icon-plugin/readme.txt", "WP SVG Icons#---#=== (WP SVG Icons|WordPress Icons (SVG)|WordPress Icons - SVG)#---#Stable tag: ([0-9.]+)#---#cpe:/a:evan-herman:svg-vector-icon-plugin",
"tablepress/readme.txt", "TablePress#---#=== TablePress#---#Stable tag: ([0-9.]+)#---#cpe:/a:tobias_baethge:tablepress",
"tabs-responsive/readme.txt", "Tabs#---#=== Tabs ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpshopsmart:tabs-responsive",
"the-events-calendar/readme.txt", "The Events Calendar#---#=== The Events Calendar#---#Stable tag: ([0-9.]+)#---#cpe:/a:modern_tribe:the-events-calendar",
"two-factor-authentication/readme.txt", "Two Factor Authentication#---#=== (Multi Step Form|Two Factor Authentication) ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:simbahosting:two-factor-authentication",
"uk-cookie-consent/readme.txt", "GDPR Cookie Consent Banner#---#=== Cookie Consent ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:termly:uk-cookie-consent",
"ultimate-faqs/readme.txt", "Ultimate FAQ#---#(=== Ultimate FAQ|[ultimate-faqs])#---#= ([0-9.]+) =#---#cpe:/a:etoilewebdesign:ultimate-faqs",
"ultimate-form-builder-lite/readme.txt", "Ultimate Form Builder Lite#---#(Easy Appointments|Ultimate Form Builder Lite)#---#Stable tag: ([0-9.]+)#---#cpe:/a:accesspressthemes:ultimate-form-builder-lite",
"ultimate-member/readme.txt", "Ultimate Member#---#=== Ultimate Member#---#Stable tag: ([0-9.]+)#---#cpe:/a:ultimatemember:ultimate-member",
"updraftplus/readme.txt", "UpdraftPlus#---#UpdraftPlus#---#Stable tag: ([0-9.]+)#---#cpe:/a:updraftplus:updraftplus",
"visitors-traffic-real-time-statistics/readme.txt", "Visitor Traffic Real Time Statistics#---#=== Visitors? Traffic Real Time Statistics#---#= ([0-9.]+) =#---#cpe:/a:wp-buy:visitors-traffic-real-time-statistics",
"visualizer/readme.txt", "Visualizer#---#=== (Visualizer|WordPress Charts and Graphs)#---#= ([0-9.]+) (- [0-9-]+ +)?=#---#cpe:/a:themeisle:visualizer",
"w3-total-cache/readme.txt", "W3 Total Cache#---#W3 Total Cache#---#Stable tag: ([0-9.]+)#---#cpe:/a:boldgrid:w3-total-cache",
"webp-express/README.txt", "WebP Express#---#=== WebP Express#---#Stable tag: ([0-9.]+)#---#cpe:/a:bitwise-it:webp-express",
"widget-logic/readme.txt", "Widget Logic#---#=== Widget Logic ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpchef:widget-logic",
"wise-chat/readme.txt", "Wise Chat#---#=== Wise Chat ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:kainex:wise-chat",
"wonderm00ns-simple-facebook-open-graph-tags/readme.txt", "Open Graph and Twitter Card Tags#---#=== Open Graph for Facebook, Google+ and Twitter Card Tags#---#Stable tag: ([0-9.]+)#---#cpe:/a:[VENDOR]:wonderm00ns-simple-facebook-open-graph-tags",
"woo-order-export-lite/readme.txt", "Advanced Order Export For WooCommerce#---#=== Advanced Order Export For WooCommerce ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:algolplus:woo-order-export-lite",
"woocommerce-checkout-manager/readme.txt", "WooCommerce Checkout Manager#---#=== WooCommerce Checkout Manager ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:quadlayers:woocommerce-checkout-manager",
"woocommerce-products-filter/readme.txt", "WOOF - Products Filter for WooCommerce#---#=== WOOF - Products Filter for WooCommerce ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:pluginus:woocommerce-products-filter",
"woocommerce/readme.txt", "WooCommerce#---#WooCommerce#---#Stable tag: ([0-9.]+)#---#cpe:/a:automattic:woocommerce",
"wordfence/readme.txt", "Wordfence Security#---#=== Wordfence Security - Firewall & Malware Scan ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wordfence:wordfence",
"wordpress-database-reset/readme.txt", "WP Database Reset#---#=== (WordPress Database Reset|WP Database Reset)#---#Stable tag: ([0-9.]+)#---#cpe:/a:webfactoryltd:wordpress-database-reset",
"wordpress-seo/readme.txt", "Yoast SEO#---#=== Yoast SEO ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:yoast:wordpress-seo",
"wp-all-import/readme.txt", "Import any XML or CSV File to WordPress#---#=== (WP All Import|Import any XML or CSV File to WordPress)#---#Stable tag: ([0-9.]+)#---#cpe:/a:soflyy:wp-all-import",
"wp-booking-system/readme.txt", "WP Booking System#---#=== WP Booking System ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:veribo:wp-booking-system",
"wp-database-backup/readme.txt", "WP Database Backup#---#=== WP Database Backup#---#= ([0-9.]+) =#---#cpe:/a:wpseeds:wp-database-backup",
"wp-editor/readme.txt", "WP Editor#---#=== WP Editor#---#Stable tag: ([0-9.]+)#---#cpe:/a:benjaminrojas:wp-editor",
"wp-fastest-cache/readme.txt", "WP Fastest Cache#---#=== WP Fastest Cache#---#Stable tag: ([0-9.]+)#---#cpe:/a:emrevona:wp-fastest-cache",
"wp-file-manager/readme.txt", "File Manager#---#=== File Manager ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:mndpsingh287:wp-file-manager",
"wp-gdpr-compliance/readme.txt", "WP GDRP Compliance#---#WP GDPR Compliance#---#Stable tag: ([0-9.]+)#---#cpe:/a:van-ons:wp-gdpr-compliance",
"wp-google-map-plugin/readme.txt", "WP Google Map Plugin#---#(WP Google Map Plugin|flippercode)#---#== Changelog(.*)#---#cpe:/a:flippercode:wp-google-map-plugin",
"wp-google-maps/readme.txt", "WP Google Maps#---#=== WP Google Maps ===#---#== Changelog(.*)#---#cpe:/a:wpgmaps:wp-google-maps",
"wp-inject/readme.txt", "ImageInject#---#ImageInject#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpscoop:wp-inject",
"wp-live-chat-support/readme.txt", "WP-Live Chat by 3CX#---#=== WP Live Chat Support ===#---#== Changelog ==.+#---#cpe:/a:3cx:wp-live-chat-support",
"wp-maintenance-mode/readme.txt", "WP Maintenance Mode#---#=== WP Maintenance Mode ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:designmodo:wp-maintenance-mode",
"wp-members/readme.txt", "WP-Members Membership Plugin#---#=== WP-Members Membership Plugin#---#Stable tag: ([0-9.]+)#---#cpe:/a:chad_butler:wp-members",
"wp-noexternallinks/readme.txt", "wp-noexternallinks#---#WP No External Links#---#Stable tag: ([0-9.]+)#---#cpe:/a:steamerdevelopment:wp-noexternallinks",
"wp-retina-2x/readme.txt", "WP Retina 2x#---#=== WP Retina 2x#---#Stable tag: ([0-9.]+)#---#cpe:/a:meowapps:wp-retina-2x",
"wp-slimstat/readme.txt", "Slimstat Analytics#---#=== (WP Slim[Ss]tat|Slimstat Analytics)#---#Stable tag: ([0-9.]+)#---#cpe:/a:jason_crouse:wp-slimstat",
"wp-smushit/readme.txt", "Smush#---#Smush Image Compression and Optimization#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpmudev:wp-smushit",
"wp-statistics/readme.txt", "WP Statistics#---#=== WP Statistics#---#Stable tag: ([0-9.]+)#---#cpe:/a:veronalabs:wp-statistics",
"wp-support-plus-responsive-ticket-system/readme.txt", "WP Support Plus Responsive Ticket System#---#=== WP Support Plus Responsive Ticket System ===#---#= V ([0-9.]+) =#---#cpe:/a:pradeep_makone:wp-support-plus-responsive-ticket-system",
"wp-ultimate-csv-importer/Readme.txt", "Import and Export WordPress Data as CSV or XML#---#Ultimate CSV Importer#---#Stable tag: ([0-9.]+)#---#cpe:/a:smackcoders:wp-ultimate-csv-importer",
"wp-ultimate-recipe/readme.txt", "WP Ultimate Recipe#---#=== WP Ultimate Recipe#---#= ([0-9.]+) =#---#cpe:/a:bootstrapped_ventures:wp-ultimate-recipe",
"wpforo/readme.txt", "wpForo Forum#---#(wpForo|Forum)#---#Stable tag: ([0-9.]+)#---#cpe:/a:gvectors:wpforo",
"wps-hide-login/readme.txt", "WPS Hide Login#---#=== WPS Hide Login#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpserveur:wps-hide-login",
"yellow-pencil-visual-theme-customizer/readme.txt", "Visual CSS Style Editor#---#=== Visual CSS Style Editor#---#= ([0-9.]+) =#---#cpe:/a:waspthemese:yellow-pencil-visual-theme-customizer",
"yikes-inc-easy-mailchimp-extender/readme.txt", "Easy Forms for Mailchimp#---#=== (Easy Forms|Easy MailChimp Forms|YIKES)#---#Stable tag: ([0-9.]+)#---#cpe:/a:yikes:yikes-inc-easy-mailchimp-extender",
"yop-poll/readme.txt", "YOP Poll#---#=== YOP Poll ===#---#= ([0-9.]+) =#---#cpe:/a:yourownprogrammer:yop-poll",
"youtube-embed-plus/readme.txt", "Embed Plus for YouTube#---#YouTube#---#Stable tag: ([0-9.]+)#---#cpe:/a:embedplus:youtube-embed-plus"
);

foreach readme( keys( plugins ) ) {
  infos = plugins[readme];
  if( ! infos )
    continue;

  infos = split( infos, sep:"#---#", keep:FALSE );
  if( ! infos || max_index( infos ) != 4 )
    continue;

  name = infos[0];
  detect_regex = infos[1];
  vers_regex = infos[2];
  cpe = infos[3];

  url = dir + "/wp-content/plugins/" + readme;
  res = http_get_cache( port: port, item: url );
  if( egrep( pattern: detect_regex, string: res, icase: TRUE ) && "Changelog" >< res ) {
    vers = eregmatch( pattern: vers_regex, string: res, icase: TRUE );
    if( ! vers[1] )
      continue;
    version = vers[1];

    kb_entry_name = ereg_replace( pattern: "/readme.txt", string: readme, replace: "", icase: TRUE );
    insloc = ereg_replace( pattern: "/readme.txt", string: url, replace: "", icase: TRUE );

    set_kb_item( name: kb_entry_name + "/detected", value: TRUE );

    extra = "Plugin Page: https://wordpress.org/plugins/" + kb_entry_name + "/";

    register_and_report_cpe( app: name,
                             ver: version,
                             concluded: ver[0],
                             base: cpe,
                             expr: "([0-9.]+)",
                             insloc: insloc,
                             regPort: port,
                             regService: "www",
                             conclUrl: url,
                             extra: extra );
  }
}


exit( 0 );
