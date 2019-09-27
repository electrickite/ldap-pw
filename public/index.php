<?php
require __DIR__ . '/../lib.php';

$fields = ['submit', 'username', 'password', 'new_password', 'confirm_password',
           'token'];

foreach ($fields as $field) {
    $$field = isset($_POST[$field]) ? $_POST[$field] : null;
}

$form = new FormState();
$form->setState($submit);

switch ($form->state()) {
    case FormState::LOGIN:
        if (authenticate($username, $password)) {
            $form->setState(FormState::UPDATE);
            $token = encryptToken($username, $password);
        } else {
            $form->setMessage('Login failed!');
        }
        break;
    case FormState::UPDATE:
        list($username, $password, $timestamp) = decryptToken($token);

        if ($timestamp < time() - 300) {
            $form->setState(FormState::FAILURE);
            $form->setMessage('Session expired.');
        } elseif ($new_password !== $confirm_password) {
            $form->setMessage('Passwords do not match!');
        } elseif (changePassword($username, $password, $new_password)) {
            $form->setState(FormState::SUCCESS);
            $form->setMessage('Password successfully updated.');
        } else {
          $form->setMessage('Could not change password!');
        }
}
?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title><?php echo $form->title(); ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family:sans-serif; }
      h1 { text-align:center; }
      form { margin:0 auto; width:300px; }
      input { box-sizing:border-box; margin-bottom:8px; padding:10px; width:100%; border:1px solid #CCC; font-size:16px; }
    </style>
  </head>
  <body>
    <form method="<?php echo $form->complete() ? 'GET' : 'POST'; ?>">
      <h1><?php echo $form->title(); ?></h1>
      <?php if ($form->message()): ?>
        <p><?php echo $form->message(); ?></p>
      <?php endif; ?>

      <?php if ($form->state() == FormState::UPDATE): ?>
        <input type="text" aria-label="Username" value="<?php echo $username; ?>" disabled>
        <input type="password" id="new_password" name="new_password" aria-label="New Password" placeholder="New Password" required>
        <input type="password" id="confirm_password" name="confirm_password" aria-label="Confirm New Password" placeholder="Confirm New Password" required>
        <input type="hidden" name="token" value="<?php echo $token; ?>">
        <input type="submit" name="submit" value="<?php echo $form->submit(); ?>">
      <?php elseif ($form->complete()): ?>
        <input type="submit" value="Ok">
      <?php else: ?>
        <input type="text" name="username" aria-label="Username" placeholder="Username" required>
        <input type="password" name="password" aria-label="Password" placeholder="Password" required>
        <input type="submit" name="submit" value="<?php echo $form->submit(); ?>">
      <?php endif; ?>
    </form>

    <?php if ($form->state() == FormState::UPDATE): ?>
      <script type="text/javascript">
        window.onload = function() {
          document.getElementById("new_password").onchange = validatePassword;
          document.getElementById("confirm_password").onchange = validatePassword;
        };

        function validatePassword() {
          var pass1 = document.getElementById("new_password");
          var pass2 = document.getElementById("confirm_password");
          if(pass1.value !== pass2.value) {
            pass2.setCustomValidity("Passwords must match");
          } else {
            pass2.setCustomValidity('');
          }
        }
      </script>
    <?php endif; ?>
  </body>
</html>
