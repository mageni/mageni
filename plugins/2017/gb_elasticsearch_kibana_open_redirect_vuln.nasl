###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elasticsearch_kibana_open_redirect_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Elasticsearch Kibana Open Redirect Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.811412");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2016-10365");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-03 20:40:53 +0530 (Mon, 03 Jul 2017)");
  script_name("Elasticsearch Kibana Open Redirect Vulnerability");

  script_tag(name:"summary", value:"This host is running Elasticsearch Kibana
  and is prone to open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation
  in kibana domain.");

  script_tag(name:"impact", value:"Successful exploitation will lead an attacker
  to craft a link in the Kibana domain that redirects to an arbitrary website.");

  script_tag(name:"affected", value:"Elasticsearch Kibana version before 4.6.3
  and 5.0.1");

  script_tag(name:"solution", value:"Upgrade to Elasticsearch Kibana version
  4.6.3 or 5.0.1 or later.");

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

if(version_is_less(version:kibanaVer, test_version:"4.6.3")){
    fix = "4.6.3";
}
else if(kibanaVer =~ "(^5\.)")
{
  if(version_is_less(version:kibanaVer, test_version:"5.0.1")){
    fix = "5.0.1";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:kibanaVer, fixed_version:fix);
  security_message(data:report, port:kibanaPort);
  exit(0);
}
exit(0);
