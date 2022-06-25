###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_solr_mult_xss_vuln01_feb16.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# Apache Solr Multiple Cross-Site Scripting Vulnerabilities-01 Feb16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:solr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806881");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2015-8795");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:30 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Solr Multiple Cross-Site Scripting Vulnerabilities-01 Feb16");

  script_tag(name:"summary", value:"This host is installed with Apache Solr and
  is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to

  - improper sanitization of user supplied input in
    'webapp/web/js/scripts/analysis.js' and 'webapp/web/js/scripts/schema-browser.js.'
    files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to to inject arbitrary web script or HTML via crafted fields.");

  script_tag(name:"affected", value:"Apache Solr versions 4.10.2, 5.0");

  script_tag(name:"solution", value:"Upgrade to Apache Solr version 5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-7346");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl");
  script_mandatory_keys("Apache/Solr/Installed");
  script_require_ports("Services/www", 8983);
  script_xref(name:"URL", value:"http://lucene.apache.org/solr");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!solrPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!solrVer = get_app_version(cpe:CPE, port:solrPort)){
  exit(0);
}

if(version_is_equal(version:solrVer, test_version:"5.0") ||
   version_is_equal(version:solrVer, test_version:"4.10.2"))
{
  report = report_fixed_ver(installed_version:solrVer, fixed_version:"5.1");
  security_message(data:report, port:solrPort);
  exit(0);
}
