Este documento explica cómo restaurar configuraciones desde los backups generados automáticamente para switches IOS-XE, firewall ASA y WLC 9800.


-------------------------

Los backups se guardan en:

outputs/backups/<familia>/<YYYY-MM-DD>/

Switches: outputs/backups/switches/YYYY-MM-DD/<hostname>.cfg
Firewall ASA: outputs/backups/firewall/YYYY-MM-DD/asa-edge.cfg
WLC: outputs/backups/wlc/YYYY-MM-DD/wlc9800.txt

Ejemplo:
Playbook: ansible/playbooks/restore_switch.yml


ansible-playbook ansible/playbooks/restore_switch.yml \
  -e "date=YYYY-MM-DD target=c9200-acc-01 replace_mode=false"

replace_mode=false → merge seguro (añade líneas faltantes).
replace_mode=true → replace completo (riesgo, requiere configure replace habilitado).

Validación post-restore:
ansible-playbook ansible/playbooks/validate_ec_and_vlan.yml



------

 Restauración de ASA
Playbook: ansible/playbooks/restore_asa.yml


ansible-playbook ansible/playbooks/restore_asa.yml \
  -e "date=YYYY-MM-DD"

Usa scripts/restore_asa.py para aplicar la configuración (merge incremental).

Verificar:
python3 scripts/validate.py --device asa --show "show running-config"




--------------------------------

Restauración de WLC 9800

Playbook: ansible/playbooks/restore_wlc.yml


ansible-playbook ansible/playbooks/restore_wlc.yml \
  -e "date=YYYY-MM-DD"


Usa scripts/restore_wlc.py para aplicar perfiles y WLANs desde el backup.


Verificar:
python3 scripts/validate.py --device wlc --show "show wlan summary"

Verificacion final:
ansible-playbook ansible/playbooks/validate_ec_and_vlan.yml



