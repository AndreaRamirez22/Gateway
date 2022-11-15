from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import  datetime
import requests
import re


app=Flask(__name__)
cors = CORS(app)
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager



app.config["JWT_SECRET_KEY"]="super-secret" #Cambiar por el que se conveniente
jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-security"]+'/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    print("ruta limpia",endPoint)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        print("Usuario del Token", usuario)
        if usuario["rol"] is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["rol"]["_id"])
            print("Permiso",tienePersmiso)
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401
def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url
def validarPermiso(endPoint,metodo,idRol):

    url=dataConfig["url-backend-security"]+"/permisos-roles/validar-permiso/rol/"+str(idRol)
    tienePermiso=False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body={
        "url":endPoint,
        "metodo":metodo
    }
    response = requests.get(url,json=body, headers=headers)
    try:
        data=response.json()
        if("_id" in data):
            tienePermiso=True
    except:
        pass
    return tienePermiso
###################################################################################


@app.route("/Mesas",methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/Mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/Mesas",methods=['POST'])
def crearMesa():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/Mesas'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/Mesas/<string:id>",methods=['GET'])
def getMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/Mesas/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/Mesas/<string:id>",methods=['PUT'])
def modificarMesa(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/Mesas/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/Mesas/<string:id>",methods=['DELETE'])
def eliminarEstudiante(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/Mesas/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


##################################################################################

@app.route("/partidos",methods=['GET'])
def getpartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/partidos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>",methods=['GET'])
def getPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/partidos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos",methods=['POST'])
def crearPartido():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/partidos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>",methods=['PUT'])
def modificarPartido(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/partidos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>",methods=['DELETE'])
def eliminarPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/partidos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


###################################################################################

##################################CANDIDATOS#######################################

@app.route("/candidatos",methods=['GET'])
def getcandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>",methods=['GET'])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/candidatos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos",methods=['POST'])
def crearCandidato():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/candidatos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>",methods=['PUT'])
def modificarCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/candidatos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>",methods=['DELETE'])
def eliminarCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/candidatos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>/Partido/<string:id_Partido>",methods=['PUT'])
def asignarPartidoACandidato(id,id_Partido):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/candidatos/' + id + '/Partido/' + id_Partido
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

###################################################################################

##################################RESULTADOS#######################################

@app.route("/resultados",methods=['GET'])
def getresultados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/resultados'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/<string:id>",methods=['GET'])
def getResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/resultados/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

"""    Asignacion Mesa y Candidato a resultado   """

@app.route("/resultados/Mesa/<string:id_Mesa>/Candidato/<string:id_Candidato>",methods=['POST'])
def crearResultado(id_Mesa,id_Candidato):
    print("crear resultado")
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/resultados/Mesa/' + id_Mesa + '/Candidato/' + id_Candidato
    print(url)
    response = requests.post(url, headers=headers,json=data)
    print(response)
    json = response.json()
    return jsonify(json)


""" Modificación de Resultado (Mesa y Candidato) """

@app.route("/resultados/<string:id_Resultado>/Mesa/<string:id_Mesa>/Candidato/<string:id_Candidato>",methods=['PUT'])
def modificarResultado(id_Resultado,id_Mesa,id_Candidato):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/resultados/'+ id_Resultado + '/Mesa/' + id_Mesa + '/Candidato/' + id_Candidato
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/resultados/<string:id_Resultado>",methods=['DELETE'])
def eliminarResultado(id_Resultado):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/resultados/' + id_Resultado
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/candidato/<string:id_Candidato>",methods=['GET'])
def resultadosEnCandidato(id_Candidato):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/resultados/' + 'candidato/'+id_Candidato
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/Mesas/<string:id_Mesa>",methods=['GET'])
def resultadosEnMesa(id_Mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/resultados/' + 'Mesas/'+ id_Mesa
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/votos_mayores",methods=['GET'])
def getMayorvotoCandidato():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria"] + '/resultados/' + 'votos_mayores'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)



###################################################################################

##################################USUARIOS##########################################


@app.route("/usuarios",methods=['GET'])
def getUsuarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['GET'])
def getUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/usuarios",methods=['POST'])
def postUsuarios():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['PUT'])
def putCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['DELETE'])
def eliminarUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>/rol/<string:id_rol>",methods=['PUT'])
def putUsuarioRol(id,id_rol):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id + '/rol/' + id_rol
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/validar",methods=['POST'])
def infoUsuario():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/validar'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)




###################################################################################

##################################ROLES##########################################


@app.route("/roles",methods=['GET'])
def getRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>",methods=['GET'])
def getRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/roles",methods=['POST'])
def postRoles():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>",methods=['PUT'])
def putRol(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>",methods=['DELETE'])
def eliminarRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)



###################################################################################

##################################PERMISOS##########################################


@app.route("/permisos",methods=['GET'])
def getPermisos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>",methods=['GET'])
def getPermiso(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/permisos",methods=['POST'])
def postPermisos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>",methods=['PUT'])
def putPermiso(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>",methods=['DELETE'])
def eliminarPermiso(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)



###################################################################################

##################################PERMISOS-ROLES####################################


@app.route("/permisos-roles",methods=['GET'])
def getPermisosRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/<string:id>",methods=['GET'])
def getPermisoRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/permisos-roles/rol/<string:id_rol>/permiso/<string:id_permiso>",methods=['POST'])
def postPermisosRoles(id_rol,id_permiso):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/rol/' + id_rol + '/permisos/' + id_permiso
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/<string:id>/rol/<string:id_rol>/permiso/<string:id_permiso>",methods=['PUT'])
def putPermisosRoles(id,id_rol,id_permiso):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/' + id + '/rol/' +id_rol + '/permiso/' + id_permiso
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/<string:id>",methods=['DELETE'])
def eliminarPermisosRoles(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/validar-permiso/rol/<string:id_rol>",methods=['GET'])
def getPermisosRoles2(id_rol):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/validar-permiso/rol/' + id_rol
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


###################################################################################

@app.route("/",methods=['GET'])
def test():
    json = {}
    json["message"]="Server running ..."
    return jsonify(json)

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data
if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])





