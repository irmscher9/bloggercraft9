from app import app, db
from flask import render_template, flash, redirect, url_for, request, Markup, jsonify
from app.models import User, Post
from app.forms import RegistrationForm, LoginForm, PostForm, ForgotPassword, NewPassword
from flask_login import current_user, login_user, logout_user, login_required
from app.token import generate_confirmation_token, confirm_token
from app.confirmemail import send_email
from werkzeug.urls import url_parse


@app.route('/', methods=['GET', 'POST'])
def index():
    page = request.args.get('page', 1, type=int)
    posts0 = Post.query.order_by(Post.upvotes.desc())
    posts = posts0.paginate(page, 10, False)
    next_url = url_for('index', page=posts.next_num) if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num) if posts.has_prev else None
    return render_template('index.html', title='Home', posts=posts, next_url=next_url, prev_url=prev_url)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are logged-in already')
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, cnf=False)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        body = render_template('emails/confirm_email_email.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(user.email, subject, body)

        login_user(user)
        flash('A confirmation email has been sent to your inbox.', 'success')
        return redirect(url_for("index"))

    return render_template('register.html', title='Register', form=form)


@app.route('/confirm')
def confirm():
    confirm_url = url_for('confirm')
    return render_template('/emails/confirm_email_email.html', title='Confirm email', confirm_url=confirm_url)


@app.route('/confirm/<token>')
def confirm_email(token):

    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.cnf:
        flash('Account already confirmed. Please login.', 'success')
        msg = 'Account already confirmed. Please ' + '<a href="/login">login</a>'
    else:
        user.cnf = True
        # db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Congratulations, you are now a registered user!', 'success')
        msg = 'You have confirmed your account. Congratulations, you are now a registered user!'
        return redirect(url_for('login'))
    return msg

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    form = ForgotPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Recovery email has been sent to your inbox!', 'success')
            token = generate_confirmation_token(user.email)
            confirm_url = url_for('recovery_password', token=token, _external=True)
            html = render_template('emails/recover_password_email.html', confirm_url=confirm_url)
            subject = "Recover your password"
            send_email(user.email, subject, html)
        else:
            flash('No user found with this email. Try again.', 'danger')

    return render_template('forgot.html', title='Forgot password', form=form)


@app.route('/recover/<token>', methods=['GET', 'POST'])
def recovery_password(token):
    try:
        email = confirm_token(token)
        user = User.query.filter_by(email=email).first()

    except:
        return 'The recovery link is invalid or has expired.'

    if user:
        form = NewPassword()
        if form.validate_on_submit():
            np = form.new_pass.data
            user.set_password(np)
            db.session.commit()
            flash('Your new password is set!', 'success')
            return redirect(url_for('login'))
    else:
        flash('New password is not set, something went wrong...', 'danger')

    return render_template('newpassword.html', title='New password', form=form)



@app.route('/profile/newpassword', methods=['GET', 'POST'])
def new_password():
    form = NewPassword()
    email = request.args.get('email')
    if current_user.is_authenticated or email:
        if form.validate_on_submit():

            user = User.query.filter_by(email=email).first()
            np = form.new_pass.data
            user.set_password(np)
            db.session.commit()
            flash('Your new password is set!', 'success')
            redirect(url_for('login'))
        else:
            flash('New password is not set, something went wrong...', 'danger')

        return render_template('newpassword.html', title='New password', form=form)

    else:
        return "Access denied!"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are logged-in')
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')

        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        flash('Successfully logged-in!', 'success')
        return redirect(next_page)

    #  url is parsed with "url_parse" to determine is the netloc component is present
    # to avoid malitious hacker attacks

    return render_template('login.html', title='Login', form=form)

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    form = PostForm()
    posts = Post.query.filter_by(user_id=current_user.id).all()
    if form.validate_on_submit():
        post = Post(body=form.post.data, author=current_user, upvotes=0)
        db.session.add(post)
        db.session.commit()
        flash('Your post is now live!', 'success')
        # flash('Your post is now live!')
        return redirect(url_for('post'))
    return render_template('post.html', title='Post', form=form, posts=posts)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/ulk')
def ulk():
    p1 = request.args.get('p1', type=int)
    ppp = request.args.get('p', type=int)

    lpost = Post.query.filter_by(id=ppp).first()
    if lpost.upvotes is None:
        lpost.upvotes = 1
    else:
        lpost.upvotes += 1
    db.session.commit()
    page = request.args.get('page', 1, type=int)
    return jsonify(page=page)


@app.route('/profile')
def profile():
    username = current_user.username
    id = current_user.id
    email = current_user.email
    return render_template('profile.html', username=username, id=id, email=email)