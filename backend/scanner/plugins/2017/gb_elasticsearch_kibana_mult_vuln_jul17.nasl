###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elasticsearch_kibana_mult_vuln_jul17.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Elasticsearch Kibana Multiple Vulnerabilities - Jul17
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:elasticsearch:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811414");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2016-1000219", "CVE-2016-1000220");
  script_bugtraq_id(99179, 99178);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-03 20:40:53 +0530 (Mon, 03 Jul 2017)");
  script_name("Elasticsearch Kibana Multiple Vulnerabilities - Jul17");

  script_tag(name:"summary", value:"This host is running Elasticsearch Kibana
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - when a custom output is configured for logging in, cookies and authorization
    headers could be written to the log files.

  - An input validation error in Kibana.");

  script_tag(name:"impact", value:"Successful exploitation will lead an attacker
  to execute arbitrary JavaScript in users' browsers, also attackers can hijack
  sessions of other users.");

  script_tag(name:"affected", value:"Elasticsearch Kibana version before 4.5.4
  and 4.1.11.");

  script_tag(name:"solution", value:"Upgrade to Elasticsearch Kibana version
  4.5.4 or 4.1.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elasticsearch_kibana_detect.nasl");
  script_mandatory_keys("Elasticsearch/Kibana/Installed");
  script_require_ports("Services/www", 5601);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!kibanaPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!kibanaVer = get_app_version(cpe:CPE, port:kibanaPort)){
 exit(0);
}

if(version_is_less(version:kibanaVer, test_version:"4.1.11")){
  fix = "4.1.11";
}
else if(kibanaVer =~ "(^4\.5)")
{
  if(version_is_less(version:kibanaVer, test_version:"4.5.4")){
    fix = "4.5.4";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:kibanaVer, fixed_version:fix);
  security_message(data:report, port:kibanaPort);
  exit(0);
}
exit(0);
