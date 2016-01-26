# -*- coding: cp1252 -*-
from flask import Flask, render_template,flash, request, redirect, url_for,session
from flask_debugtoolbar import DebugToolbarExtension
from wtforms import Form, TextField, PasswordField, BooleanField, validators, TextAreaField, SelectField, HiddenField
from passlib.hash import sha256_crypt, bcrypt
import hashlib
from MySQLdb import escape_string as thwart
from dbconnect import connection
from confconnect import confconnection
import sys
from datetime import datetime, date, time,timedelta
import random, string


reload(sys)  
sys.setdefaultencoding('Cp1252')

app = Flask(__name__)

app.config['SECRET_KEY'] = 'jkfdjkfdjkdfjkdfgvkdofglndflkjkn'
app.config['DEBUG_TB_ENABLED'] = False
toolbar = DebugToolbarExtension(app)

class FrontPage(Form):
    firstname = TextField('Fornavn')
    lastname = TextField('Etternavn')
    contact = TextField('Kontaktperson')
    company = TextField('Firma')
    phonenumber = TextField('Telefonnummer')
    rnummer = TextField('Ressursnummer')

class LoginForm(Form):
    username = TextField('Brukernavn',[validators.Length(min=3,max=8),validators.Required()])
    password = PasswordField('Passord',[validators.Length(min=3,max=20), validators.Required()])

class EditGjestForm(Form):
    kortnr = TextField('Kortnummer')
    firstname = TextField('Fornavn')
    lastname = TextField('Etternavn')
    contact = TextField('Kontaktperson')
    company = TextField('Firma')
    phonenumber = TextField('Telefonnummer')
    comment = TextAreaField('Merknad')
    ssid = TextField('SSID')

class NewPersonIDCard(Form):
    fornavn = TextField('Fornavn')
    etternavn = TextField('Etternavn')
    telefonnummer = TextField('Telefonummer')
    firma = TextField('Firma')
    leder = TextField('Leder')
    korttype = SelectField(u'Type',choices=[('a','Ansatt'),('b','Intern'),('i','Innleid'),('e','Ekstern'),('s','Service')])
    serienummer = TextField('Serienummer', [validators.Required()])
    kode = TextField('Kode:', [validators.Required()])
    sykkelbod = SelectField(u'Sykkelbod', choices=[('nei','Nei'),('ja','Ja')])
    arkiv = SelectField(u'Arkiv', choices=[('nei','Nei'),('ja','Ja')])
    boder = SelectField(u'Boder', choices=[('nei','Nei'),('ja','Ja')])
    tsst = SelectField(u'TSST', choices=[('nei','Nei'),('ja','Ja')])
    opm = SelectField(u'OPM', choices=[('nei','Nei'),('ja','Ja')])


class EditGuestCardForm(Form):
    kortnr = TextField('Kortnr')
    serienummer = TextField('Serienummer')
    kode = TextField('Kode')
    korttype = SelectField(u'Korttype', choices=[('intern','Intern'),('ekstern','Ekstern'),('service','Service'),('opm','OPM')])
    tilgang = SelectField(u'Tilgang', choices=[('fast','Fast ansatt'),('midl','Midlertidlig'),('ekst','Ekstern'),('service','Service')])
    sperret = BooleanField('Sperret')

class EndreKortnummerForm(Form):
    newnumber = TextField('Nytt kortnummer:')

class EncryptPass(Form):
    password = TextField(u'Password')

class NewVisitorCardForm(Form):
    kortnr = TextField(u'Kortnr',[validators.Required(),validators.Length(min=4)])
    serienummer = TextField(u'Serienummer',[validators.Length(min=4,max=15)])
    kode = TextField(u'Kode')
    type = SelectField(u'KortType',choices=[('intern','Intern'),('ekstern','Ekstern'),('opm','OPM'),('s','Service'),('Renhold','Renhold')])
    adgang = SelectField(u'Adgang', choices=[('Felles','Felles'),('opm','OPM'),('renhold','Renhold'),('service','Service')])
    kommentar = TextAreaField(u'Kommentar')
        

def FindCardType(kortnr):
    c, conn = connection() 
    data = c.execute("SELECT type from kort WHERE kortnr=%s",thwart(kortnr))
    data = c.fetchone()[0]
    conn.close()
    return data

def FindCode(kortnr):
    c, conn = connection()
    data = c.execute("SELECT kode FROM kort WHERE kortnr=%s",thwart(kortnr))
    data = c.fetchone()[0]
    conn.close()
    return data

def CreateLog(site,detail):
    try:
        c,conn = confconnection()
        c.execute("INSERT INTO log (date,time,user,site,ip,detail_id) VALUES (%s,%s,%s,%s,%s,%s)",(datetime.now().strftime('%Y/%m/%d'),datetime.now().strftime('%H:%M'),session['user'],site,request.remote_addr,detail))
        conn.commit()
        conn.close()
    except Exception as e:
        return (str(e))


@app.route('/santa/')
def santa():

    return render_template('christmas.html')

def TimeCheck():
    now = datetime.now().strftime('%H%M')
    openAfter = 0700
    closeAfter = 1245
    if  now >= openAfter and now <= closeAfter:
        print ""
    else:
        return redirect(url_for('santa'))


def CardAlreadyOut(kortnr):

    c,conn = connection()
    data = c.execute("SELECT kortnr, kvittert FROM adgang WHERE kortnr=%s AND kvittert=%s",(kortnr,'1'))
    conn.close()
    if int(data) == 1:
        return True
    else:
        return False


    
@app.route('/', methods=['GET','POST'])
def homepage():
    try:
        #TimeCheck()
        #return redirect(url_for('santa')) DETTE ER FOR NEDSTENGING AV JULETIDER

        ##Interne kort uten IDkort
        c, conn = connection()
        ikort = c.execute("SELECT * FROM kort WHERE type=(%s) OR type=(%s) and mottatt =(%s) and showList=(%s) and sperret=(%s) ORDER BY kortnr ASC",('intern','system','0','1','0'))
        ikort = c.fetchall()
        conn.close()
        ##SLUTT##

        ##Interne kort med IDkort##
        c, conn = connection()
        idkort = c.execute("SELECT * FROM kort WHERE type=(%s) OR type=(%s) and mottatt =(%s) and showList=(%s) and sperret=(%s) ORDER BY kortnr ASC",('intern','system','0','1','0'))
        idkort = c.fetchall()
        conn.close()
        ##SLUTT##

        ##Eksterne kort##
        c, conn = connection()
        ekort = c.execute("SELECT * FROM kort WHERE type='ekstern' and mottatt =(%s) and showList=(%s) and sperret=(%s) ORDER BY kortnr ASC",('0','1','0'))
        ekort = c.fetchall()
        conn.close()
        ##SLUTT##

        ##Service kort##
        c, conn = connection()
        skort = c.execute("SELECT * FROM kort WHERE type='service' and mottatt =(%s) and showList=(%s) and sperret=(%s) ORDER BY kortnr ASC",('0','1','0'))
        skort = c.fetchall()
        conn.close()
        ##SLUTT##

        ##OPM kort##
        c, conn = connection()
        opmkort = c.execute("SELECT * FROM kort WHERE type='opm' and mottatt =(%s) and showList=(%s) and sperret=(%s) ORDER BY kortnr ASC",('0','1','0'))
        opmkort = c.fetchall()
        conn.close()
        ##SLUTT##

        form = FrontPage(request.form)
        
        if request.method == "POST" and form.validate():
            c, conn = connection()
            if request.form['regtype'] == "intern" or request.form['regtype'] == "ekstern" or request.form['regtype'] == "opm" or request.form['regtype'] == "service":
                c.execute("INSERT INTO adgang (navn, etternavn, firma, kontakt, telefon, dato_inn, tid_inn, kvittert, kortnr, public, ssid, korttype, edit) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                              (thwart(request.form['firstname']),
                               thwart(request.form['lastname']),
                               thwart(request.form['company']),
                               thwart(request.form['contact']),
                               thwart(request.form['phonenumber']),
                               datetime.now().strftime('%Y/%m/%d'),
                               datetime.now().strftime('%H:%M:%S'),
                               '1', #kvittert
                               thwart(request.form['kortnr']),
                               '1', #public
                               ('%06x' % random.randrange(16**30)),
                               FindCardType(request.form['kortnr']), #search cardtype
                               'Registrert'))
                c.execute("UPDATE kort SET mottatt=(%s) WHERE kortnr =(%s)",('1',request.form['kortnr']))
           


            if request.form['regtype'] == "idkort":
               c.execute("INSERT INTO adgang (navn, firma, dato_inn, tid_inn, kvittert, kortnr, public, ssid, korttype, edit) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                              (thwart('Ressursnummer: %s' %(request.form['rnummer'])),
                               thwart('Jernbaneverket'),
                               datetime.now().strftime('%Y/%m/%d'),
                               datetime.now().strftime('%H:%M:%S'),
                               '1', #kvittert
                               thwart(request.form['kortnr']),
                               '1', #public
                               ('%06x' % random.randrange(16**30)),
                               FindCardType(request.form['kortnr']), #search cardtype
                               'Registrert'))
               c.execute("UPDATE kort SET mottatt=(%s) WHERE kortnr =(%s)",('1',request.form['kortnr']))
                                      
            conn.commit()
            conn.close()
            return redirect(url_for('Step2'))
    except Exception as e:
        return (str(e))
    myip = request.remote_addr
    return render_template('main.html', form=form, ikort=ikort, idkort=idkort,ekort=ekort,skort=skort,opmkort=opmkort,myip=myip)

@app.route('/step2/')
def Step2():
    time = 5
    return render_template('step2.html', time=time)

@app.route('/crypt/', methods=['GET','POST'])
def crypt():
    try:
        
        form = EncryptPass(request.form)
        if request.method == "POST":
             data = bcrypt.encrypt(request.form['password'])
             return render_template('encrypt.html',form=form, data=data)
    except Exception as e:
        return (str(e))
    return render_template('encrypt.html',form=form)

def FindPass(username):
    #c,conn = connection()
    c,conn = confconnection()
    data = c.execute("SELECT * FROM users WHERE username = (%s)",(thwart(username)))
    data = c.fetchone()[2]
    passw = hashlib.sha1(data)
    conn.close()
    return passw.hexdigest()

def FindCode(cardnumber):
    c,conn = connection()
    data = c.execute("SELECT kode from kort WHERE kortnr=(%s)",(thwart(cardnumber)))
    data = c.fetchone()[0]
    conn.close()
    return data

def SetPermissions(username):
    #c, conn = connection()
    c,conn = confconnection()
    c.execute("SELECT * FROM new_users WHERE username=(%s)",(thwart(username)))
    datas = c.fetchall()
    for data in datas:
        session['developer'] = data[5] #Set developer
        session['access'] = data[4] #Set accessgroup
        session['deliver_card'] = data[6] #deliver_card - lever inn kort
        session['guest_edit'] = data[7] #eguest_edit - endrer besOksprofilene
        session['guestcard_edit'] = data[8] #guest_card_edit - endrer besOkskortene
        session['guest_search'] = data[9] #guest_search - sok etter besOkskort
        session['guestcard_delete'] = data[14] #Sletting av gjestekort
        session['show_code']= data[10] #show_code
        session['edit_card'] = data[11] #endrer PID
        session['add_card'] = data[12] #add_Card
        session['user_edit'] = data[13] #User_Edit - Legger til og registrerer nye brukere.


"""
@app.route('/login/', methods=['GET','POST'])
def LoginPage():
    form = LoginForm(request.form) 
    try:
        if request.method == "POST" and form.validate():
            username = request.form['username']
            password = request.form['password']
            #c, conn = connection() 
            try:
                c,conn = confconnection()
                data = c.execute("SELECT password FROM new_users WHERE username = (%s)",(thwart(username)))
                data = c.fetchone()[0]
                passw = hashlib.sha1(password)
                if passw.hexdigest() == str(data):
                    session['logged_in'] = True
                    session['user'] = username
                    setUserName = username #For use in logging
                    SetPermissions(username)
                    CreateLog("Login",username)
                    conn.close()
                    return redirect(url_for('Profile'))
                else:
                    flash("Feil brukernavn eller passord!")
            except Exception as e:
                return (str(e))
    except Exception as e:
           return (str(e))   

    return render_template('login.html', form=form)
"""
userUpdate = 0
@app.route('/login/', methods=['GET','POST'])
def LoginPage():
    form = LoginForm(request.form) 
    try:
        if request.method == "POST" and form.validate():
            username = thwart(request.form['username'])
            c,conn = confconnection()
            data = c.execute("SELECT password, username FROM new_users WHERE username =(%s)",(username))
            #CheckForOldPass(username,request.form['password'])
            data = c.fetchone()
            passw = request.form['password']
            if c.rowcount == 0:
                return CheckForOldPass(username,passw)
            elif(bcrypt.verify(passw,data[0])):
                session['logged_in'] = True
                session['user'] = username
                setUserName = username #For use in logging
                SetPermissions(username)
                CreateLog("Login",username)
                conn.close()
                return redirect(url_for('Profile'))
            else:
                CreateLog('Wrong password',setUserName)
                return "Feil brukernavn eller passord"
    except Exception as e:
        return (str(e))
    return render_template('login.html', form = form, usrUpdate = userUpdate, userMessage="Det ble utf&oslash;rt en n&oslash;dvendig brukeroppdatering, venligst logg inn igjen")


def CheckForOldPass(username,oldpass):
    try:
        c,conn = confconnection()
        data = c.execute("SELECT * FROM users WHERE Login=%s",(username))
        data = c.fetchone()

        SetNewPass(username,data[2],oldpass,data[6],data[17],data[13],data[43],data[27],data[29],data[24],data[11],data[9],data[21])
        userUpdate = 1
        return redirect(url_for('LoginPage'))
    except Exception as e:
        return (str(e))       

#app.route('/SetNewPass/',methods=['GET','POST'])
def SetNewPass(username,name,password, access,developer,deliver_card,guest_edit,guestcard_edit,guest_search,show_code,edit_card,add_card,user_edit):
    #form = SetPassClass(request.form)
    try:
        c,conn = confconnection()
        c.execute("INSERT INTO new_users (username,name, password, access,developer,deliver_card,guest_edit,guestcard_edit,guest_search,show_code,edit_card,add_card,user_edit) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(username,name,bcrypt.encrypt(password),access,developer,deliver_card,guest_edit,guestcard_edit,guest_search,show_code,edit_card,add_card,user_edit))
        conn.commit()
        conn.close()
        CreateLog('Convert pass to bcrypt',username)
        return redirect(url_for('LoginPage',userMessage="Det ble utf&oslash;rt en n&oslash;dvendig brukeroppdatering, venligst logg inn igjen"))

    except Exception as e:
        return (str(e))




@app.route('/logout/')
def LogOut():
    try:
        session.clear()
        return redirect(url_for('LoginPage'))
    except Exception as e:
        return (str(e))

@app.route('/profile/')
def Profile():
    try:
        if session['logged_in'] != True:
            return redirect(url_for('LoginPage'))
        else:
            return render_template('profile.html')
    except Exception as e:
        return (str(e))

def DateBetween(t = None,*args, **kwargs):
    format = "%Y/%m/%d"
    now = datetime.now().strftime(format)
    cardTime = datetime.strptime(t,format)
    delta = now-cardTime
    return delta.days

    

@app.route('/list_gjester/', methods=['GET','POST'])
def List_Gjester():

    try:
        c, conn = connection()
        data = c.execute("SELECT * from adgang WHERE kvittert=(%s) ORDER BY kortnr ASC",'1')
        rows = c.fetchall()
        return render_template('list_gjester.html',rows=rows, date = datetime.now().strftime('%Y/%m/%d'))
        conn.close()
    except Exception as e:
        return (str(e))

@app.route('/leverkort/', methods=['GET','POST'])
def LeverKort():
    try:
        kortnr = request.args['k']
        ssid = request.args['ssid']
        c,conn = connection()
        c.execute("UPDATE kort SET mottatt=(%s) WHERE kortnr =(%s)",('0',kortnr))
        c.execute("UPDATE adgang SET kvittert=(%s), ut=(%s), tid_ut=(%s) WHERE ssid =(%s)",('0',
                                                                                            datetime.now().strftime('%Y/%m/%d'),
                                                                                            datetime.now().strftime('%H:%M:%S'),
                                                                                            ssid))
        conn.commit()
        conn.close()
        CreateLog("Deliver card",kortnr)
        return redirect(url_for('List_Gjester'))
    except Exception as e:
        return (str(e))

@app.route('/endregjest/', methods=['GET','POST'])
def Endre_Gjest():        
    form = EditGjestForm(request.form)
    ssid = request.args['ssid']
    kortnr = request.args['kortnr']
    kode = FindCode(kortnr)
    c, conn = connection()
    c.execute("SELECT * FROM adgang WHERE ssid=(%s)",(ssid))
    rows = c.fetchall()
    conn.close()
    CreateLog("Edit guest",kortnr)
    return render_template('endre_gjest.html',rows=rows, form = form, kode=kode)

@app.route('/executeguest/', methods=['GET','POST'])
def Execute_Guest():
    try:
        if request.method == "POST":
            try:
                c, conn = connection()
                c.execute("UPDATE adgang SET navn=(%s),etternavn=(%s),firma=(%s),kontakt=(%s),telefon=(%s), merknad=(%s), edit=(%s) WHERE ssid=(%s)",(
                request.form['navn'],
                request.form['etternavn'],
                request.form['firma'],
                request.form['kontakt'],
                request.form['telefon'],
                request.form['merknad'],
                session['user'],request.form['ssid']))
                
                conn.commit()
                conn.close()

                return redirect(url_for('List_Gjester'))
            except Exception as e:
                return (str(e))
    except Exception as e:
        return (str(e))
    return redirect(url_for('Profile'))

@app.route('/cardlog/', methods=['GET','POST'])
def CardLog():
    try:
        c,conn = connection()
        c.execute("SELECT * FROM adgang ORDER BY id DESC")
        data = c.fetchall()
        conn.close()
        return render_template('cardlog.html',rows=data, status='')
    except Exception as e:
        return (str(e))
@app.route('/newpid/', methods=['GET','POST'])
def newPID():
    try:
        form = NewPersonIDCard(request.form)
        if request.method == "POST":
            c,conn = connection()
            x = c.execute("INSERT INTO personalkort (fornavn, etternavn, telefon, firma, leder, type, serienr, legitimasjon, sykkelbod, arkiv, boder, tsst, opm) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                          (thwart(request.form['fornavn']),
                           thwart(request.form['etternavn']),
                           thwart(request.form['telefonnummer']),
                           thwart(request.form['firma']),
                           thwart(request.form['leder']),
                           thwart(request.form['korttype']),
                           thwart(request.form['serienummer']),
                           thwart(request.form['kode']),
                           thwart(request.form['sykkelbod']),
                           thwart(request.form['arkiv']),
                           thwart(request.form['boder']),
                           thwart(request.form['tsst']),
                           thwart(request.form['opm'])))
            conn.commit()
            conn.close()
            if x == 1:
                CreateLog("New PID",request.form['fornavn'] + " " + request.form['etternavn'] + " (" + request.form['serienummer'] + ")")
                flash("Brukeren er registrert")
            else:
                flash("Error")
    except Exception as e:
        return (str(e))
    return render_template('newpersonid.html', form=form)

@app.route('/showcode/')
def ShowCode():
    try:
        c,conn = connection()
        c.execute("SELECT kortnr, type, kode FROM kort WHERE type =(%s) OR type=(%s) OR type=(%s) ORDER BY kortnr ASC",('intern','ekstern','service'))
        data = c.fetchall()
        return render_template('showcode.html',rows=data)
    except Exception as e:
         return (str(e))

@app.route('/ForceCard/', methods=['GET','POST'])
def ForceCard():
    kortnr = request.args['kortnr']
    try:
        c,conn = connection()
        c.execute("UPDATE kort SET mottatt=%s WHERE kortnr=%s",('0',kortnr))
        c.execute("UPDATE adgang SET kvittert=%s WHERE kortnr=%s",('0',kortnr))
        conn.commit()
        conn.close()
        CreateLog("Force Card-deliver",kortnr)
        return "Kortet er tvunget innlevert."
    except Exception as e:
        return (str(e))

@app.route('/search/', methods=['GET','POST'])
def Search():
    try:
        if request.method == 'POST':
            CreateLog("Search Card",request.form['mySearch'])
            c,conn = connection()
            x = c.execute("SELECT * FROM kort WHERE kortnr = (%s)",(request.form['mySearch']))
            data = c.fetchall()
            conn.close()
            return render_template('cardsearch.html',data=data)
    except Exception as e:
        return (str(e))
    return render_template('cardsearch.html',data=data)

@app.route('/deletevisitorcard/',methods=['GET','POST'])
def deletevisitorcard():
    kortnr = thwart(request.args['kortnr'])
    c,conn = connection()
    c.execute("DELETE FROM kort WHERE kortnr=(%s)",kortnr)
    conn.commit()
    conn.close()
    CreateLog('Deleted card',kortnr)
    return"Kortet er slettet"


@app.route('/editguestcard/', methods=['GET','POST'])
def editguestcard():
    try:
        kortnr = request.args['kortnr']
        c,conn = connection()
        c.execute("SELECT * FROM kort WHERE kortnr = (%s)", (kortnr))
        rows = c.fetchall()
        conn.close()                      

        return render_template('editguestcard.html', rows=rows)
    except Exception as e:
        return (str(e))

@app.route('/executeeditguestcard/', methods=['GET','POST'])
def executeeditguestcard():
    try:
        c,conn = connection()
        if request.method == "POST":
            c.execute("UPDATE kort SET kortnr=(%s),type=(%s),serie=(%s),kode=(%s),adgang=(%s),showList=(%s),sperret=(%s) WHERE id=(%s)",
                          (thwart(request.form['kortnr']),
                           thwart(request.form['type']),
                           thwart(request.form['serienr']),
                           thwart(request.form['kode']),
                           thwart(request.form['adgang']),
                           thwart(request.form['showList']),
                           thwart(request.form['sperret']),
                           thwart(request.form['id'])))
            conn.commit()
            conn.close()
            CreateLog("Edit Card",request.form['kortnr'])
            return redirect(url_for('List_Gjester'))
    except Exception as e:
        return (str(e))

@app.route('/endrekortnummer/', methods=['GET','POST'])
def endrekortnummer():
    oldnr = request.args['kortnr']
    ssid = request.args['ssid']
        
    return render_template('endrekortnummer.html',oldnr=oldnr, ssid=ssid)

@app.route('/executeendrekortnummer/', methods=['GET','POST'])
def executeendrekortnummer():
    try:
        
        if request.method == "POST":
            c,conn = connection()
            endrettext = "Kortnummeret er blitt endret fra %s til %s" % (request.form['oldnr'], request.form['newnumber'])
            c.execute("UPDATE adgang SET kortnr =(%s), merknad=(%s),edit=(%s) WHERE ssid=(%s)",
                      (request.form['newnumber'],
                       endrettext,
                       session['user'],
                       request.form['ssid']))
                       
            c.execute("UPDATE kort SET mottatt =(%s) WHERE kortnr=(%s)",('0',request.form['oldnr']))
            c.execute("UPDATE kort SET mottatt =(%s) WHERE kortnr=(%s)",('1',request.form['newnumber']))
            conn.commit()
            conn.close()
            CreateLog('Transfer cardnumber', request.form['oldnr'] + " to " + request.form['newnumber'])

            return redirect(url_for('List_Gjester'))

    except Exception as e:
        return (str(e))

@app.route('/newvisitorcard/', methods=['GET','POST'])
def NewVisitorCard():
    form = NewVisitorCardForm(request.form)
    try:
       if request.method == "POST" and form.validate():
           try:
               c,conn = connection()
               c.execute("INSERT INTO kort (kortnr,serie,kode,type,adgang,kommentar,mottatt,showList,sperret) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                         (thwart(request.form['kortnr']),
                          thwart(request.form['serienummer']),
                          thwart(request.form['kode']),
                          thwart(request.form['type']),
                          thwart(request.form['adgang']),
                          thwart(request.form['kommentar']),
                          '0',
                          '1',
                          '0'))
               conn.close()
               CreateLog('New visitorcard',request.form['kortnr'])
               return "Kortet er lagt til!"
           except:
              return "Det har skjedd en feil"
    except Exception as e:
        return (str(e))
    return render_template('newvisitorcard.html',form=form)
    
    




    #################ADMINISTRATION#################

class AddUserForm(Form):
    username = TextField('Brukernavn',[validators.Length(min=4,max=12),validators.Required()])
    name = TextField('Navn')
    email = TextField('Email',[validators.Required()])
    password = PasswordField('Passord', [validators.Length(min=6),validators.EqualTo('confirm', message=('Passordene samsvarer ikke'))])
    confirm = PasswordField('Gjenta passord')
    access = SelectField(u'Brukergruppe', choices=[('user','Bruker'),('admin','Admin'),('opm','OPM'),('opmadmin','OPMAdmin')])

@app.route('/admin/')
def AdminPage():
    try:
        if session['access'] != 'admin':
            session.clear()
            return redirect(url_for('LoginPage'))

        return render_template('admin/main.html')
    except Exception as e:
        return (str(e))

@app.route('/admin/AddUser/', methods=['GET','POST'])
def AddUser():
    try:
        form = AddUserForm(request.form)
        c,conn = confconnection()
        if request.method == "POST" and form.validate():
            passwd = hashlib.sha1(thwart(request.form['password']))
            passwd = passwd.hexdigest()
            x = c.execute("INSERT INTO users (Login, Password, Name, Email, access, developer, edit_card_detail, guest_card_edit,guest_search, show_code,edit_card,add_card,user_edit) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                      (thwart(request.form['username']),
                       passwd,
                       thwart(request.form['name']),
                       thwart(request.form['email']),
                       thwart(request.form['access']),
                       '0', #developer
                       '1', #edit_card_detail
                       '0', #guest_card_edit
                       '1', #guest_search
                       '1', #show_code
                       '0', #edit_card
                       '0', #add_card
                       '0' #user_edit
                       ))
            conn.commit()
            conn.close()
            CreateLog('Add user',request.form['username'])
            return "Brukeren er lagt til, husk rettighetsetting"



        return render_template('admin/adduser.html', form=form)
    except Exception as e:
        return (str(e))

@app.route('/admin/ListUsers/')
def ListUsers():
    try:
        c,conn = confconnection()
        data = c.execute("SELECT * FROM users")
        data = c.fetchall()
        conn.close()
        return render_template('admin/listusers.html',data=data)
    except Exception as e:
        return (str(e))

@app.route('/admin/EditUser/', methods=['GET','POST'])
def EditUser():
    try:
        selectedUser = request.args["id"]
        c,conn = confconnection()
        data = c.execute("SELECT * FROM users WHERE id=%s",thwart(selectedUser))
        data = c.fetchall()
        conn.close()
        return render_template('admin/edituser.html',data=data)
    except Exception as e:
        return (str(e))

@app.route('/admin/edituser-exec/', methods=['GET','POST'])
def UserExec():
    try:
        c,conn = confconnection()
        if request.method == "POST":
            c.execute("UPDATE users SET Name=%s,Login=%s,access=%s,canLogin=%s,developer=%s,edit_card_detail=%s,guest_card_edit=%s,show_code=%s,user_edit=%s WHERE id=%s",(thwart(request.form['name']),thwart(request.form['login']),thwart(request.form['access']),thwart(request.form['canLogin']),thwart(request.form['developer']),thwart(request.form['guest_edit']),thwart(request.form['guestcard_edit']),thwart(request.form['show_code']),thwart(request.form['user_edit']),thwart(request.form['userid'])))
            conn.commit()
            conn.close()
            CreateLog('Edit user',request.form['username'])
            return redirect(url_for('ListUsers'))
    except Exception as e:
        return (str(e))
@app.route('/admin/userlog/')
def UserLog():
    try:
        c,conn = confconnection()
        data = c.execute("SELECT * FROM log")
        data = c.fetchall()
        conn.close()
        CreateLog('Userlog','All')

        return render_template('admin/userlog.html', data=data)

    except Exception as e:
        return (str(e))
    
    return render_template('admin/userlog.html', data=data)
@app.route('/admin/userlog/truncate/')
def EmptyLog():
    try:
        c,conn = confconnection()
        c.execute("TRUNCATE TABLE log")
        conn.commit()
        conn.close()
        CreateLog('Empty log','Everything')
        return redirect(url_for('UserLog'))
    except Exception as e:
        return (str(e))
        



if __name__ == "__main__":

    app.run(debug=False)