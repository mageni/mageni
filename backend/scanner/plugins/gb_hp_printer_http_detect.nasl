# Copyright (C) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103675");
  script_version("2022-02-16T13:39:14+0000");
  script_tag(name:"last_modification", value:"2022-02-17 11:13:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2013-03-07 14:31:24 +0100 (Thu, 07 Mar 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of HP Printers.");

  exit(0);
}

include("host_details.inc");
include("hp_printers.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

urls = get_hp_detect_urls();

foreach url (keys(urls)) {
  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if (match = eregmatch(pattern: pattern, string: res, icase: TRUE)) {
    set_kb_item(name: "hp/printer/detected", value: TRUE);
    set_kb_item(name: "hp/printer/http/detected", value: TRUE);
    set_kb_item(name: "hp/printer/http/port", value: port);

    model = "unknown";
    fw_version = "unknown";

    if (!isnull(match[5])) {
      model = match[5];
      set_kb_item(name: "hp/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "hp/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    } else if (!isnull(match[4])) {
      model = match[4];
      set_kb_item(name: "hp/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "hp/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    } else if (!isnull(match[3])) {
      model = match[3];
      set_kb_item(name: "hp/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "hp/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    } else if (isnull(match[3]) && !isnull(match[2])) {
      model = match[2];
      set_kb_item(name: "hp/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "hp/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    } else {
      model = match[1];
      set_kb_item(name: "hp/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "hp/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    }

    model = chomp(model);
    model = ereg_replace(string: model, pattern: "( Wide Format)?( All-in-One)?( Printer)?( Series)?",
                         replace: "", icase: TRUE);

    if ("Server: HP HTTP Server" >< res) {
      vers = eregmatch(pattern: 'Server: HP HTTP Server.*\\{([^},]+).*\\}[\r\n]+', string: res);
      if (!isnull(vers[1])) {
        fw_version = vers[1];
        set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
        set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
      }
    } else if ('<strong id="FirmwareRevision">' >< res) {
      vers = eregmatch(pattern: '<strong id="FirmwareRevision">([0-9_]+)', string: res);
      if(!isnull(vers[1])) {
        fw_version = vers[1];
        set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
        set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
      }
    } else if ('<strong id="FirmwareRevision">' >< res) {
      vers = eregmatch(pattern: '<strong id="FirmwareRevision">([0-9_]+)', string: res);
      if (!isnull(vers[1])) {
        fw_version = vers[1];
        set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
        set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
      }
    } else if ('<strong id="FutureSmartBundleVersion">' >< res) {
      # <strong id="FutureSmartBundleVersion">5.2.0.2</strong>
      vers = eregmatch(pattern: '<strong id="FutureSmartBundleVersion">([0-9.]+)', string: res);
      if (!isnull(vers[1])) {
        fw_version = vers[1];
        set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
        set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
      }
    }

    if (fw_version == "unknown") {
      url = "/jd_diag.htm";
      res = http_get_cache(port: port, item: url);
      # <td > Firmware Version: </td> <td > V.37.18 </td>
      vers = eregmatch(pattern: "Firmware Version\s*:\s*</td>[^>]+>\s*V\.([0-9.]+)[^>]+>", string: res);
      if (!isnull(vers[1])) {
        fw_version = vers[1];
        set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
        set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
      } else {
        url = "/hp/device/webAccess/index.htm?content=auto_firmware_update_manifest";
        res = http_get_cache(port: port, item: url);
        vers = eregmatch(pattern: "<b>Firmware version:&nbsp;</b>([A-Z0-9_.]+)<br/><b>Published:",
                         string: res);
        if (!isnull(vers[1])) {
          fw_version = vers[1];
          set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
          set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                      value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
        } else {
          url = "/DevMgmt/ProductConfigDyn.xml";
          res = http_get_cache(port: port, item: url);
          vers = eregmatch(pattern: "<prdcfgdyn:ProductInformation>.*<dd:Version>\s*<dd:Date>([^<]+)</dd:Date>",
                           string: res);
          if (!isnull(vers[1])) {
            fw_version = vers[1];
            fw_version = str_replace(string: fw_version, find: "-", replace: "");
            set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
            set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                        value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
          } else {
            # <prdcfgdyn:ProductInformation> <dd:Version> <dd:Revision>SAYAADPP1N001.2144D.00</dd:Revision> <dd:Date>2021-12-21</dd:Date>
            vers =  eregmatch(pattern: "<prdcfgdyn:ProductInformation>\s*<dd:Version>\s*<dd:Revision>([^<]+)</dd:Revision>",
                              string: res);
            if (!isnull(vers[1])) {
              fw_version = vers[1];
              set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
              set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                          value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
            } else {
              url = "/info_configuration.html";
              res = http_get_cache(port: port, item: url);
              vers = eregmatch(pattern: ">Firmware Datecode:</td>[^>]+>([^<]+)</td>", string: res);
              if (!isnull(vers[1])) {
                fw_version = vers[1];
                set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
                set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                            value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
              } else {
                url = "/hp/jetdirect/index.html";
                res = http_get_cache(port: port, item: url);
                # Firmware Version:</b> </td> <td > V.37.12 </td>
                vers = eregmatch(pattern: "Firmware Version:</b>[^>]+>[^>]+>\s*V\.([0-9.]+)", string: res);
                if (!isnull(vers[1])) {
                  fw_version = vers[1];
                  set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
                  set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                              value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
                } else {
                  url = "/hp/device/this.LCDispatcher?nav=hp.Config";
                  res = http_get_cache(port: port, item: url);
                  # Firmware:</div> <div class="hpDataItemValue">  20141230 07.191.8</div>
                  vers = eregmatch(pattern: "Firmware:</div>[^>]+>\s*[0-9]+\s+([0-9.]+)<", string: res);
                  if (!isnull(vers[1])) {
                    fw_version = vers[1];
                    set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
                    set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                                value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
                  } else {
                    url = "/hp/device/this.LCDispatcher?dispatch=html&cat=0&pos=1";
                    res = http_get_cache(port: port, item: url);
                    # Firmware Datecode:  20010524 01.016.0
                    vers = eregmatch(pattern: "Firmware Datecode\s*:\s*[0-9]+\s+([0-9.]+)", string: res);
                    if (!isnull(vers[1])) {
                      fw_version = vers[1];
                      set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
                      set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
                    } else {
                      url = "/hp/device/FirmwareUpgrade";
                      res = http_get_cache(port: port, item: url);
                      # <label>Firmware Revision</label> <p id="FirmwareRevision">2308214_000901</p>
                      vers = eregmatch(pattern: 'id="FirmwareRevision">([0-9_]+)<', string: res);
                      if (!isnull(vers[1])) {
                        fw_version = vers[1];
                        set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
                        set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
                      } else {
                        url = "/hp/device/InternalPages/Index?id=ConfigurationPage";
                        res = http_get_cache(port: port, item: url);
                        # id="FirmwareRevision">2308214_000907<
                        vers = eregmatch(pattern: 'id="FirmwareRevision">([0-9_]+)<', string: res);
                        if (!isnull(vers[1])) {
                          fw_version = vers[1];
                          set_kb_item(name: "hp/printer/http/" + port + "/versConcluded", value: vers[0]);
                          set_kb_item(name: "hp/printer/http/" + port + "/versConcludedUrl",
                                      value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    set_kb_item(name: "hp/printer/http/" + port + "/model", value: model);
    set_kb_item(name: "hp/printer/http/" + port + "/fw_version", value: fw_version);

    exit(0);
  }
}

banner = http_get_remote_headers(port: port);

# nb: The HP HTTP Server banner is already evaluated above, it is just kept here as a fallback...
# Server: HP HTTP Server; OfficeJet Pro 7740 series - G5J38A; Serial Number: CN92M351FT; Built: Fri Jul 13, 2018 10:46:29AM {EDWINXPP1N002.1828A.00}
# SERVER: HP-ChaiSOE/1.0
# Server: HP-ChaiServer/3.0
if (concl = egrep(pattern: "^Server\s*:\s*(HP HTTP Server;|HP-Chai)", string: banner, icase: TRUE)) {
  concl = chomp(concl);

  set_kb_item(name: "hp/printer/detected", value: TRUE);
  set_kb_item(name: "hp/printer/http/detected", value: TRUE);
  set_kb_item(name: "hp/printer/http/port", value: port);

  model = "unknown";
  fw_version = "unknown";

  set_kb_item(name: "hp/printer/http/" + port + "/model", value: model);
  set_kb_item(name: "hp/printer/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "hp/printer/http/" + port + "/generalConcluded", value: concl);
}

exit(0);
