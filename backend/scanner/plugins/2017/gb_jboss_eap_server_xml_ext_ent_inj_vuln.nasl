###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jboss_eap_server_xml_ext_ent_inj_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# RedHat JBoss Enterprise Application Platform XML External Entity Injection Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107199");
  script_version("$Revision: 14175 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-22 17:05:17 +0200 (Mon, 22 May 2017)");
  script_cve_id("CVE-2017-7464");
  script_bugtraq_id(98450);

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("RedHat JBoss Enterprise Application Platform XML External Entity Injection Vulnerability");
  script_tag(name:"summary", value:"RedHat JBoss Enterprise Application Platform (EAP) is prone to an
  XML External Entity injection vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"When parsing XML which does entity expansion the SAXParserFactory
  used in EAP expands external entities, even when XMLConstants.FEATURE_SECURE_PROCESSING is set to true.");

  script_tag(name:"impact", value:"Attackers can exploit this  issue to gain access to sensitive information
  or cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Red Hat JBoss EAP server EAP 7.0.5 and 7.1.0");

  script_tag(name:"solution", value:"Mitigation: Enable the security features of the DocumentBuilderFactory or SaxParserFactory as described by OWASP below.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98450");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#JAXP_DocumentBuilderFactory.2C_SAXParserFactory_and_DOM4J");

  script_tag(name:"solution_type", value:"Mitigation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_red_hat_jboss_eap_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Redhat/JBoss/EAP/Installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! Port = get_app_port( cpe:CPE ) ) {
  exit( 0 );
}

if( ! Ver = get_app_version( cpe:CPE, port:Port ) ) {
  exit( 0 );
}

if ( Ver =~ "7\.0" ) {
  if ( version_is_less( version: Ver, test_version:"7.0.5" ) ) {
    Vuln = TRUE;
  }
} else if ( Ver =~ "7\.1" ) {
  if ( version_is_less( version: Ver, test_version:"7.1.0" ) ) {
    Vuln = TRUE;
  }
}

if( Vuln ) {
  report = report_fixed_ver( installed_version:Ver, fixed_version:"Mitigation" );
  security_message( port:Port, data:report );
  exit( 0 );
}

exit ( 99 );
