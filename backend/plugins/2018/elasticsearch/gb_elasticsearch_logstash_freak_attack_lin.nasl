###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elasticsearch_logstash_freak_attack_lin.nasl 12045 2018-10-24 06:51:17Z mmartin $
#
# Elasticsearch Logstash 'CVE-2015-5378' Man in the Middle Security Bypass Vulnerability (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:elasticsearch:logstash";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107279");
  script_version("$Revision: 12045 $");
  script_bugtraq_id(76015);
  script_cve_id("CVE-2015-5378");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 08:51:17 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-31 14:18:58 +0100 (Wed, 31 Jan 2018)");
  script_name("Elasticsearch Logstash 'CVE-2015-5378' Man in the Middle Security Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"Elasticsearch Logstash is prone to security-bypass vulnerability.

  This script has been merged into the NVT 'Elasticsearch Logstash 'CVE-2015-5378' Man in the Middle Security Bypass Vulnerability'
  (OID: 1.3.6.1.4.1.25623.1.0.107278)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the usage of Lumberjack input
  (in combination with Logstash Forwarder agent)");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow attackers
  to perform unauthorized actions by conducting a man-in-the-middle attack. This may lead
  to other attacks.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Elasticsearch Logstash version prior to
  1.5.3 or 1.4.4 on Linux.");

  script_tag(name:"solution", value:"Users should upgrade to 1.5.3 or 1.4.4. Users that do not
  want to upgrade can address the vulnerability by disabling the Lumberjack input.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/76015/");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_elastsearch_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("logstash/installed", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE))){
  exit(0);
}

if(!version = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version =~ "^1\.4\."){
  if(version_is_less(version:version, test_version:"1.4.3")){
    report = report_fixed_ver(installed_version:version, fixed_version:"1.4.3");
  }
}

if(version =~ "^1\.5\.") {
  if(version_is_less(version:version, test_version:"1.5.3")){
    report = report_fixed_ver(installed_version:version, fixed_version:"1.5.3");
  }
}

if (report != "") {
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
