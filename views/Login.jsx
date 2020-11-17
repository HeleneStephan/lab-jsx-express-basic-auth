const React = require("react");
const Layout = require("./Layout");

function Login(props) {
  return (
    <Layout>
      <form id="form" action="/auth/login" method="POST">
        <label>Username</label>
        <br />
        <input type="text" name="username" placeholder="username" />

        <label>Password</label>
        <br />
        <input type="password" name="password" placeholder="password" />

        <button type="submit">Login</button>
      </form>

      {props.errorMessage ? (
        <div className="error-message"> {props.errorMessage}</div>
      ) : null}

      <p className="account-message">
        You don't have an account? <a href="/auth/signup">Sign up</a>
      </p>
    </Layout>
  );
}

module.exports = Login;
