###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wso2_carbon_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# WSO2 Carbon Products Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106178");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-10 12:16:07 +0700 (Mon, 10 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WSO2 Carbon Products Detection");

  script_tag(name:"summary", value:"Detection of WSO2 Carbon based Products

The script sends a connection request to the server and attempts to detect the presence of WSO2 Carbon based
products and the version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 9443);
  script_mandatory_keys("WSO2_Carbon/banner");

  script_xref(name:"URL", value:"http://wso2.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 9443);

banner = get_http_banner(port: port);

if ("Server: WSO2 Carbon Server" >< banner) {
  url = "/carbon/product/about.html";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("<title>WSO2 " >< res) {
    prod = eregmatch(pattern: "About WSO2 ([^<]+)", string: res);
    if (isnull(prod[1]))
      exit(0);

    prod = chomp(prod[1]);

    if (prod == "Identity Server") {
      kb_name = 'wso2_carbon_identity_server';
      cpe = 'cpe:/a:wso2:carbon_identity_server';
      app = "WSO2 Identity Server";
    }
    else if (prod == "ESB") {
      kb_name = 'wso2_carbon_enterprise_service_bus';
      cpe = 'cpe:/a:wso2:carbon_enterprise_service_bus';
      app = "WSO2 Enterprise Service Bus";
    }
    else if (prod == "Data Analytics Server") {
      kb_name = 'wso2_carbon_data_analytics_server';
      cpe = 'cpe:/a:wso2:carbon_data_analytics_server';
      app = "WSO2 Data Analytics Server";
    }
    else if (prod == "API Manager") {
      kb_name = 'wso2_carbon_api_manager';
      cpe = 'cpe:/a:wso2:carbon_api_manager';
      app = "WSO2 API Manager";
    }
    else if (prod == "Complex Event Processor") {
      kb_name = 'wso2_carbon_complex_event_processor';
      cpe = 'cpe:/a:wso2:carbon_complex_event_processor';
      app = "WSO2 Complex Event Processor";
    }
    else if (prod == "Governance Registry") {
      kb_name = 'wso2_carbon_governance_registry';
      cpe = 'cpe:/a:wso2:carbon_goverannce_registry';
      app = "WSO2 Governance Registry";
    }
    else if (prod == "Business Process Server") {
      kb_name = 'wso2_carbon_business_process_server';
      cpe = 'cpe:/a:wso2:carbon_business_process_server';
      app = "WSO2 Business Process Server";
    }
    else if (prod == "Storage Server") {
      kb_name = 'wso2_carbon_storage_server';
      cpe = 'cpe:/a:wso2:carbon_storage_server';
      app = "WSO2 Storage Server";
    }
    ## TODO: Some carbon based servers are not identifiable through this method.
    else
      exit(0);

    set_kb_item(name: kb_name + '/installed', value: TRUE);

    version = "unknown";

    vers = eregmatch(pattern: "<h1>Version ([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: kb_name + '/version', value: version);
      cpe = cpe + ':' + version;
    }
    else if (prod == "Storage Server") {
      vers = eregmatch(pattern: "Storage Server Version ([0-9.]+)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: kb_name + '/version', value: version);
        cpe = cpe + ':' + version;
      }
    }

    register_product(cpe: cpe, location: "/carbon", port: port);

    log_message(data: build_detection_report(app: app, version: version, install: "/carbon", cpe: cpe,
                                             concluded: vers[0]),
                port: port);

    exit(0);
  }
}

exit(0);
