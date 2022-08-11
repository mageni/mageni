# Copyright (C) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106156");
  script_version("2020-04-09T08:43:52+0000");
  script_tag(name:"last_modification", value:"2020-04-09 11:12:54 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"creation_date", value:"2016-07-29 09:30:37 +0700 (Fri, 29 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei VRP Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Huawei Versatile Routing Platform (VRP) devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name:"URL", value:"http://e.huawei.com/en/products/enterprise-networking/switches");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);
sysdesc = snmp_get_sysdesc(port: port);
if (!sysdesc)
  exit(0);

if (sysdesc =~ "Huawei Versatile Routing Platform( Software)?") {
  # Quidway S2403H-EI Product Version S2403H-EI-0020P02
  mo = eregmatch(pattern: "Quidway (S[0-9]+([A-Z-]+)?)", string: sysdesc);
  if (!isnull(mo[1]))
    model = mo[1];
  else {
    # Some switches have the model at the beginning e.g.
    # S12712
    # Huawei Versatile Routing Platform Software
    # VRP (R) Software, Version 5.170 (S12700 V200R010C00SPC600)
    # VRP (R) Software, Version 3.30(SBC V200R005C03SPC400)
    if (egrep(pattern: "\(S(12700|2700|5700|6720|BC) V", string: sysdesc)) {
      mo = eregmatch(pattern: '^([^\r\n]+)', string: sysdesc);
      if (!isnull(mo[1]))
        model = chomp(mo[1]);
      else
        exit(0);
    } else {
      # Huawei Versatile Routing Platform
      # Software Version: VRP (R) software, Version 5.30 USG6350 V100R001C20SPC700
      mo = eregmatch(pattern: "(USG[0-9]{4}) V", string: sysdesc);
      if (!isnull(mo[1]))
        model = mo[1];
      else {
        # Huawei Versatile Routing Platform Software
        # VRP (R) software, Version 5.120 (ATN V600R006C00SPC300)
        # ATN980
        mo = eregmatch(pattern: "(ATN[0-9-]+)", string: sysdesc);
        if (!isnull(mo[1]))
          model = mo[1];
        else {
          mo = eregmatch(pattern: "\(([A-Z0-9-]+) ", string: sysdesc);
          if (!isnull(mo[1]))
            model = mo[1];
          else {
            # Software Version: VRP (R) software, Version 5.30 Eudemon1000E-X3 V300R001C00
            mo = eregmatch(pattern:"(Eudemon[^ ]+)", string: sysdesc);
            if (!isnull(mo[1]))
              model = mo[1];
            else
              exit(0);
          }
        }
      }
    }
  }

  version = "unknown";
  vers = eregmatch(pattern: 'Version [0-9.]+[^\r\n]*(V[0-9A-Z]+)', string: sysdesc);
  if (!isnull(vers[1]))
    version = vers[1];

  patch = eregmatch(pattern: 'Patch.*(V[A-Z0-9]+)', string: sysdesc);
  if (!isnull(patch[1])) {
    patch_version = patch[1];
  } else {
    patch_version = "No patch installed";
  }

  set_kb_item(name: "huawei/vrp/detected", value: TRUE);
  set_kb_item(name: "huawei/vrp/snmp/detected", value: TRUE);
  set_kb_item(name: "huawei/vrp/snmp/port", value: port);

  set_kb_item(name: "huawei/vrp/snmp/" + port + "/model", value: model);
  set_kb_item(name: "huawei/vrp/snmp/" + port + "/version", value: version);
  set_kb_item(name: "huawei/vrp/snmp/" + port + "/patch", value: patch_version);
  set_kb_item(name: "huawei/vrp/snmp/" + port + "/concluded", value: sysdesc);

  exit(0);
}

exit(0);
