###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyfaq_xss_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# phpMyFAQ Multiple XSS And CSRF Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:phpmyfaq:phpmyfaq';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140387");
  script_version("$Revision: 11983 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-21 16:15:51 +0700 (Thu, 21 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2017-14618", "CVE-2017-14619", "CVE-2017-15809", "CVE-2017-15808",
                "CVE-2017-15735", "CVE-2017-15734", "CVE-2017-15732", "CVE-2017-15733",
                "CVE-2017-15731", "CVE-2017-15730", "CVE-2017-15729", "CVE-2017-15728",
                "CVE-2017-15727");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ Multiple XSS And CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"The host is running phpMyFAQ and is prone
  to multiple XSS and CSRF vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Cross-site scripting (XSS) vulnerability in inc/PMF/Faq.php in phpMyFAQ
    allows remote attackers to inject arbitrary web script or HTML via the
    Questions field in an 'Add New FAQ' action script or HTML via the
    'Title of your FAQ' field in the Configuration Module.

  - Cross-site scripting (XSS) vulnerability in phpMyFAQ allows remote attackers
    to inject arbitrary web.

  - XSS in admin/tags.main.php via a crafted tag.

  - CSRF in admin/ajax.config.php.

  - Cross-Site Request Forgery (CSRF) for modifying a glossary.

  - Cross-Site Request Forgery (CSRF) in admin/stat.main.php.

  - Cross-Site Request Forgery (CSRF) in admin/news.php.

  - Cross-Site Request Forgery (CSRF) in admin/ajax.attachment.php and admin/att.main.php.

  - Cross-Site Request Forgery (CSRF) in admin/stat.adminlog.php.

  - Cross-Site Request Forgery (CSRF) in admin/stat.ratings.php.

  - Cross-Site Request Forgery (CSRF) for adding a glossary.

  - Stored Cross-site Scripting (XSS) via metaDescription or metaKeywords.

  - Stored Cross-site Scripting (XSS) via an HTML attachment.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct XSS and CSRF attacks.");

  script_tag(name:"affected", value:"phpMyFAQ version 2.9.8 and prior.");

  script_tag(name:"solution", value:"Upgrade to phpMyFAQ version 2.9.9 or later.");

  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/commit/30b0025e19bd95ba28f4eff4d259671e7bb6bb86");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/commit/cb648f0d5690b81647dd5c9efe942ebf6cce7da9");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.9.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
